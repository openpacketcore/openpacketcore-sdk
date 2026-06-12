//! Durable, SQLite-backed audit sink for alarm admin actions (enabled by the
//! `persist` feature). Satisfies the fail-closed audit contract of
//! `AlarmAuditSink`: if the append to the `alarm_audit` table fails, the
//! manager abandons the suppression/acknowledgement. Free-text audit fields
//! (principal, reason, correlation id) are scrubbed of long digit runs and
//! IPv4 literals before persistence as a defense-in-depth layer on top of
//! caller-side RFC 010 redaction.

use crate::manager::{AlarmActionScope, AlarmAuditEvent, AlarmAuditOutcome, AlarmAuditSink};
use opc_persist::SqliteBackend;
use time::format_description::well_known::Rfc3339;

/// A persist-backed audit sink implementing [`AlarmAuditSink`].
///
/// It serializes administrative alarm action audit events durably to the
/// `alarm_audit` table of a [`SqliteBackend`] database, preserving redaction requirements
/// by scrubbing raw sensitive values (SUPIs/phone numbers/IPs) from audit fields.
pub struct PersistAlarmAuditSink {
    backend: SqliteBackend,
}

impl PersistAlarmAuditSink {
    /// Create a new persist-backed alarm audit sink.
    pub fn new(backend: SqliteBackend) -> Self {
        Self { backend }
    }
}

impl AlarmAuditSink for PersistAlarmAuditSink {
    fn record_alarm_action(&mut self, event: AlarmAuditEvent) -> Result<(), String> {
        let action_str = match event.action {
            crate::manager::AlarmAction::Acknowledge => "acknowledge",
            crate::manager::AlarmAction::Suppress => "suppress",
        };

        let outcome_str = match event.outcome {
            AlarmAuditOutcome::Authorized => "authorized",
            AlarmAuditOutcome::Denied => "denied",
        };

        let scope_str = match &event.scope {
            AlarmActionScope::Alarm { alarm_id } => format!("alarm:{alarm_id}"),
            AlarmActionScope::Tenant { tenant } => format!("tenant:{tenant}"),
            AlarmActionScope::Global => "global".to_string(),
        };

        let occurred_at_str = event
            .occurred_at
            .format(&Rfc3339)
            .map_err(|e| format!("Failed to format timestamp: {e}"))?;

        // Redact principal, reason, and correlation_id to prevent leaking sensitive values
        let redacted_principal = redact_sensitive_string(&event.principal);
        let redacted_reason = redact_sensitive_string(&event.reason);
        let redacted_correlation_id = event.correlation_id.as_deref().map(redact_sensitive_string);

        let backend = self.backend.clone();
        let action_str = action_str.to_string();
        let outcome_str = outcome_str.to_string();
        let alarm_id_str = event.alarm_id.as_str().to_string();
        let alarm_type_str = event.alarm_type.as_str().to_string();
        let probable_cause_str = event.probable_cause.to_string();
        let tenant_str = event.tenant.clone();

        let handle = tokio::runtime::Handle::try_current()
            .map_err(|e| format!("No tokio runtime handle available: {e}"))?;

        let result = std::thread::spawn(move || {
            handle.block_on(async move {
                backend
                    .record_alarm_audit(
                        &action_str,
                        &outcome_str,
                        &alarm_id_str,
                        &alarm_type_str,
                        &probable_cause_str,
                        &redacted_principal,
                        tenant_str.as_deref(),
                        &redacted_reason,
                        &scope_str,
                        redacted_correlation_id.as_deref(),
                        &occurred_at_str,
                    )
                    .await
                    .map_err(|e| format!("Database audit append failed: {e}"))
            })
        })
        .join()
        .map_err(|e| format!("Thread join failed: {e:?}"))?;

        result
    }
}

/// Redact sequences of 8+ consecutive digits (SUPIs/phone numbers) and IPv4 addresses.
fn redact_sensitive_string(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // Check for 8+ consecutive digits
        let mut digit_count = 0;
        while i + digit_count < chars.len() && chars[i + digit_count].is_ascii_digit() {
            digit_count += 1;
        }
        if digit_count >= 8 {
            result.push_str("[REDACTED]");
            i += digit_count;
            continue;
        }

        // Check for IPv4 pattern at chars[i...]
        if let Some(ipv4_len) = match_ipv4(&chars[i..]) {
            result.push_str("[REDACTED]");
            i += ipv4_len;
            continue;
        }

        result.push(chars[i]);
        i += 1;
    }
    result
}

fn match_ipv4(slice: &[char]) -> Option<usize> {
    let mut idx = 0;
    for part in 0..4 {
        if part > 0 {
            if idx >= slice.len() || slice[idx] != '.' {
                return None;
            }
            idx += 1;
        }
        let mut part_len = 0;
        while idx < slice.len() && slice[idx].is_ascii_digit() && part_len < 3 {
            idx += 1;
            part_len += 1;
        }
        if part_len == 0 {
            return None;
        }
    }
    Some(idx)
}
