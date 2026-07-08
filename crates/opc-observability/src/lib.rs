//! Reusable tracing subscriber setup for OpenPacketCore CNFs.
//!
//! The crate installs a single global subscriber with a runtime-reloadable
//! [`EnvFilter`], formatted stderr output, and structural field redaction
//! before fields are rendered.
//!
//! # Runtime wiring
//!
//! Consumers using `opc-runtime` can install logging during `ProcessInit` by
//! using the helper from `opc-runtime`:
//!
//! ```rust,ignore
//! use opc_runtime::{Builder, RuntimeProfile, StartupPhases};
//!
//! # fn build(profile: RuntimeProfile) -> Builder {
//! let phases = StartupPhases {
//!     init_logging: Some(opc_runtime::init_observability_logging(Some("info"))),
//!     ..StartupPhases::default()
//! };
//!
//! Builder::new(profile).with_phases(phases)
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::fmt;
use std::sync::{Mutex, OnceLock, RwLock};

use opc_redaction::{redact_text, RedactionSummary};
use thiserror::Error;
use tracing::field::{Field, Visit};
use tracing_subscriber::field::{RecordFields, VisitOutput};
use tracing_subscriber::fmt::format::{FormatFields, Writer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

/// Default verbosity used when neither an explicit directive nor `RUST_LOG`
/// is present, and when a malformed initial directive is supplied.
pub const DEFAULT_DIRECTIVE: &str = "info";

type ReloadHandle = reload::Handle<EnvFilter, Registry>;

static INIT_LOCK: Mutex<()> = Mutex::new(());
static RELOAD: OnceLock<ReloadHandle> = OnceLock::new();
static CURRENT: RwLock<String> = RwLock::new(String::new());

/// Errors raised while configuring or reloading observability.
#[derive(Debug, Error)]
pub enum ObservabilityError {
    /// A runtime filter directive could not be parsed.
    #[error("invalid tracing directive {directive:?}: {source}")]
    InvalidDirective {
        /// Directive supplied by the caller.
        directive: String,
        /// Parser error returned by `tracing-subscriber`.
        #[source]
        source: tracing_subscriber::filter::ParseError,
    },

    /// The global subscriber could not be installed.
    #[error("failed to install tracing subscriber: {0}")]
    Init(#[source] tracing_subscriber::util::TryInitError),

    /// The reload handle is unavailable because this crate did not initialize
    /// the global subscriber.
    #[error("observability subscriber is not initialized")]
    NotInitialized,

    /// The active subscriber disappeared or its reload lock was poisoned.
    #[error("failed to reload tracing directive: {0}")]
    Reload(#[source] tracing_subscriber::reload::Error),
}

/// Install the global tracing subscriber.
///
/// This is idempotent for subscribers installed by this crate: calling it after
/// a successful install is a no-op. The initial directive is resolved as:
/// explicit argument, then `RUST_LOG`, then [`DEFAULT_DIRECTIVE`]. A malformed
/// initial directive falls back to [`DEFAULT_DIRECTIVE`] so logging is not
/// accidentally disabled.
pub fn init(cli_directive: Option<&str>) -> Result<(), ObservabilityError> {
    let _guard = INIT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if RELOAD.get().is_some() {
        return Ok(());
    }

    let requested = resolve_initial_directive(cli_directive, rust_log_env());
    let (filter, resolved) = initial_filter(&requested);
    let (filter_layer, handle) = reload::Layer::new(filter);
    let fmt_layer = redacting_fmt_layer().with_writer(std::io::stderr);

    Registry::default()
        .with(filter_layer)
        .with(fmt_layer)
        .try_init()
        .map_err(ObservabilityError::Init)?;

    let _ = RELOAD.set(handle);
    set_current(&resolved);
    Ok(())
}

/// Hot-swap the active filter directive.
///
/// Bad directives fail closed: the existing filter remains active and
/// [`current_directive`] is unchanged.
pub fn set_directive(directive: &str) -> Result<String, ObservabilityError> {
    let filter = parse_filter(directive)?;
    let handle = RELOAD.get().ok_or(ObservabilityError::NotInitialized)?;

    handle.reload(filter).map_err(ObservabilityError::Reload)?;
    set_current(directive);
    Ok(directive.to_string())
}

/// Return the currently applied directive.
#[must_use]
pub fn current_directive() -> String {
    CURRENT
        .read()
        .ok()
        .map(|current| current.clone())
        .filter(|current| !current.is_empty())
        .unwrap_or_else(|| DEFAULT_DIRECTIVE.to_string())
}

fn rust_log_env() -> Option<String> {
    std::env::var("RUST_LOG").ok()
}

fn resolve_initial_directive(cli_directive: Option<&str>, env_directive: Option<String>) -> String {
    cli_directive
        .and_then(non_empty)
        .map(str::to_string)
        .or_else(|| {
            env_directive
                .as_deref()
                .and_then(non_empty)
                .map(str::to_string)
        })
        .unwrap_or_else(|| DEFAULT_DIRECTIVE.to_string())
}

fn non_empty(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn initial_filter(requested: &str) -> (EnvFilter, String) {
    match parse_filter(requested) {
        Ok(filter) => (filter, requested.to_string()),
        Err(_) => (
            EnvFilter::builder()
                .with_regex(false)
                .parse(DEFAULT_DIRECTIVE)
                .unwrap_or_else(|_| EnvFilter::new(DEFAULT_DIRECTIVE)),
            DEFAULT_DIRECTIVE.to_string(),
        ),
    }
}

fn parse_filter(directive: &str) -> Result<EnvFilter, ObservabilityError> {
    EnvFilter::builder()
        .with_regex(false)
        .parse(directive)
        .map_err(|source| ObservabilityError::InvalidDirective {
            directive: redact_error_text(directive),
            source,
        })
}

fn set_current(directive: &str) {
    if let Ok(mut current) = CURRENT.write() {
        *current = directive.to_string();
    }
}

fn redact_error_text(value: &str) -> String {
    let mut summary = RedactionSummary::default();
    redact_text(value, &mut summary)
}

fn redacting_fmt_layer<S>() -> tracing_subscriber::fmt::Layer<S, RedactingFields>
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    tracing_subscriber::fmt::layer()
        .with_target(true)
        .fmt_fields(RedactingFields)
}

/// Field formatter that redacts values before the fmt layer renders them.
#[derive(Debug, Default)]
pub struct RedactingFields;

impl<'writer> FormatFields<'writer> for RedactingFields {
    fn format_fields<R: RecordFields>(&self, writer: Writer<'writer>, fields: R) -> fmt::Result {
        let mut visitor = RedactingVisitor::new(writer);
        fields.record(&mut visitor);
        visitor.finish()
    }

    fn add_fields(
        &self,
        current: &'writer mut tracing_subscriber::fmt::FormattedFields<Self>,
        fields: &tracing::span::Record<'_>,
    ) -> fmt::Result {
        if !current.fields.is_empty() {
            current.fields.push(' ');
        }
        self.format_fields(current.as_writer(), fields)
    }
}

impl RedactingFields {
    fn format_redacted_debug(&self, field: &Field, value: &dyn fmt::Debug) -> RedactedDebugValue {
        let rendered = format!("{value:?}");
        RedactedDebugValue(redact_field_value(field.name(), &rendered))
    }
}

#[derive(Debug)]
struct RedactingVisitor<'writer> {
    writer: Writer<'writer>,
    fields: RedactingFields,
    is_empty: bool,
    result: fmt::Result,
}

impl<'writer> RedactingVisitor<'writer> {
    fn new(writer: Writer<'writer>) -> Self {
        Self {
            writer,
            fields: RedactingFields,
            is_empty: true,
            result: Ok(()),
        }
    }

    fn maybe_pad(&mut self) {
        if self.is_empty {
            self.is_empty = false;
        } else {
            self.result = write!(self.writer, " ");
        }
    }
}

impl Visit for RedactingVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        if self.result.is_err() {
            return;
        }

        let value = RedactedDebugValue(redact_field_value(field.name(), value));
        self.record_debug(field, &value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if self.result.is_err() {
            return;
        }

        let name = field.name();
        if name.starts_with("log.") {
            return;
        }

        let value = self.fields.format_redacted_debug(field, value);
        self.maybe_pad();

        self.result = if name == "message" {
            write!(self.writer, "{value:?}")
        } else if let Some(raw_name) = name.strip_prefix("r#") {
            write!(self.writer, "{raw_name}={value:?}")
        } else {
            write!(self.writer, "{name}={value:?}")
        };
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.record_debug(field, &format_args!("{value}"));
    }
}

impl VisitOutput<fmt::Result> for RedactingVisitor<'_> {
    fn finish(self) -> fmt::Result {
        self.result
    }
}

struct RedactedDebugValue(String);

impl fmt::Debug for RedactedDebugValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn redact_field_value(field_name: &str, value: &str) -> String {
    let mut summary = RedactionSummary::default();
    let redaction_input = if is_sensitive_field_name(field_name) {
        format!("{field_name}={value}")
    } else {
        value.to_string()
    };

    let redacted = redact_text(&redaction_input, &mut summary);
    if is_sensitive_field_name(field_name) {
        redacted
            .split_once('=')
            .map(|(_, value)| value.to_string())
            .unwrap_or(redacted)
    } else {
        redacted
    }
}

fn is_sensitive_field_name(field_name: &str) -> bool {
    let normalized = field_name
        .trim_start_matches("r#")
        .chars()
        .filter(|ch| *ch != '_' && *ch != '-' && *ch != '.')
        .flat_map(char::to_lowercase)
        .collect::<String>();

    matches!(
        normalized.as_str(),
        "supi"
            | "gpsi"
            | "imsi"
            | "msisdn"
            | "nai"
            | "pei"
            | "imei"
            | "imeisv"
            | "privatekey"
            | "apikey"
            | "secretkey"
            | "clientsecret"
            | "password"
            | "authorization"
            | "token"
            | "accesskey"
            | "secret"
    ) || normalized.ends_with("token")
        || normalized.ends_with("secret")
        || normalized.ends_with("key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Debug, Clone, Default)]
    struct BufferWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl BufferWriter {
        fn output(&self) -> String {
            let buffer = self
                .buffer
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            String::from_utf8_lossy(&buffer).to_string()
        }
    }

    impl io::Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut buffer = self
                .buffer
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            buffer.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for BufferWriter {
        type Writer = BufferWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn directive_precedence_defaults_to_info() {
        assert_eq!(resolve_initial_directive(None, None), DEFAULT_DIRECTIVE);
    }

    #[test]
    fn directive_precedence_uses_rust_log_without_arg() {
        assert_eq!(
            resolve_initial_directive(None, Some("warn,opc=debug".to_string())),
            "warn,opc=debug"
        );
    }

    #[test]
    fn directive_precedence_arg_overrides_rust_log() {
        assert_eq!(
            resolve_initial_directive(Some("debug"), Some("warn".to_string())),
            "debug"
        );
    }

    #[test]
    fn bad_initial_directive_falls_back_to_default() {
        let (_, resolved) = initial_filter(",!");
        assert_eq!(resolved, DEFAULT_DIRECTIVE);
    }

    #[test]
    fn bad_runtime_directive_is_rejected() {
        assert!(matches!(
            parse_filter(",!"),
            Err(ObservabilityError::InvalidDirective { .. })
        ));
    }

    #[test]
    fn invalid_directive_error_redacts_directive_text() {
        let err = parse_filter("bad directive imsi=001010000000001,!")
            .expect_err("directive should be invalid");
        let rendered = format!("{err:?} {err}");
        assert!(
            rendered.contains("[REDACTED_SUBSCRIBER_ID]"),
            "directive error was not redacted: {rendered}"
        );
        assert!(
            !rendered.contains("001010000000001"),
            "directive error leaked raw IMSI: {rendered}"
        );
    }

    #[test]
    fn init_and_runtime_set_directive_round_trip() {
        init(Some("info")).unwrap();
        assert_eq!(current_directive(), "info");

        let applied = set_directive("debug").unwrap();
        assert_eq!(applied, "debug");
        assert_eq!(current_directive(), "debug");

        let err = set_directive(",!");
        assert!(matches!(
            err,
            Err(ObservabilityError::InvalidDirective { .. })
        ));
        assert_eq!(current_directive(), "debug");
    }

    #[test]
    fn redaction_visitor_redacts_sensitive_fields() {
        let writer = BufferWriter::default();
        let subscriber = Registry::default().with(
            redacting_fmt_layer()
                .with_writer(writer.clone())
                .without_time()
                .with_ansi(false),
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(imsi = "001010000000001", normal = "allowed", "attach");
        });

        let output = writer.output();
        assert!(
            output.contains("[REDACTED_SUBSCRIBER_ID]"),
            "output was not redacted: {output}"
        );
        assert!(
            !output.contains("001010000000001"),
            "raw IMSI leaked: {output}"
        );
        assert!(
            output.contains("normal=allowed"),
            "normal field lost: {output}"
        );
    }

    #[test]
    fn redaction_visitor_redacts_sensitive_text_values() {
        let writer = BufferWriter::default();
        let subscriber = Registry::default().with(
            redacting_fmt_layer()
                .with_writer(writer.clone())
                .without_time()
                .with_ansi(false),
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(peer = "imsi=001010000000001", "context");
        });

        let output = writer.output();
        assert!(
            output.contains("[REDACTED_SUBSCRIBER_ID]"),
            "text value was not redacted: {output}"
        );
        assert!(
            !output.contains("001010000000001"),
            "raw IMSI leaked: {output}"
        );
    }

    #[test]
    fn redaction_visitor_preserves_snake_case_error_codes() {
        let writer = BufferWriter::default();
        let subscriber = Registry::default().with(
            redacting_fmt_layer()
                .with_writer(writer.clone())
                .without_time()
                .with_ansi(false),
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(
                error_code = "swu_ike_auth_child_sa_negotiation_failed",
                opaque_blob = "q83KLcP0uVwF+7aTq83KLcP0uVwF+7aTq83KLcP0uVw=",
                "fail-closed"
            );
        });

        let output = writer.output();
        assert!(
            output.contains("error_code=swu_ike_auth_child_sa_negotiation_failed"),
            "diagnostic error code was hidden: {output}"
        );
        assert!(
            output.contains("opaque_blob=[REDACTED_SECURITY_SECRET]"),
            "high-entropy token was not redacted: {output}"
        );
        assert!(
            !output.contains("q83KLcP0uVwF+7aTq83KLcP0uVwF+7aTq83KLcP0uVw="),
            "raw token leaked: {output}"
        );
    }
}
