//! Durable, SQLite-backed audit sink for alarm admin actions (enabled by the
//! `persist` feature). Satisfies the fail-closed audit contract of
//! `AlarmAuditSink`: if the append to the `alarm_audit` table fails, the
//! manager abandons the suppression/acknowledgement. Free-text audit fields
//! (principal, reason, correlation id) are scrubbed with the shared
//! `opc-redaction` classifier before persistence as a defense-in-depth layer on
//! top of caller-side RFC 010 redaction.

use crate::manager::{AlarmActionScope, AlarmAuditEvent, AlarmAuditOutcome, AlarmAuditSink};
use opc_persist::SqliteBackend;
use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc;
use time::format_description::well_known::Rfc3339;

/// A persist-backed audit sink implementing [`AlarmAuditSink`].
///
/// It serializes administrative alarm action audit events durably to the
/// `alarm_audit` table of a [`SqliteBackend`] database, preserving redaction requirements
/// by scrubbing raw sensitive values (SUPIs/phone numbers/IPs) from audit fields.
pub struct PersistAlarmAuditSink {
    tx: Option<mpsc::Sender<AuditAppendRequest>>,
    worker: Option<std::thread::JoinHandle<()>>,
    startup_error: Option<String>,
}

struct AuditAppendRequest {
    event: PersistAuditEvent,
    result_tx: mpsc::Sender<Result<(), String>>,
}

struct PersistAuditEvent {
    action: String,
    outcome: String,
    alarm_id: String,
    alarm_type: String,
    probable_cause: String,
    principal: String,
    tenant: Option<String>,
    reason: String,
    scope: String,
    correlation_id: Option<String>,
    occurred_at: String,
}

impl PersistAlarmAuditSink {
    /// Create a new persist-backed alarm audit sink.
    pub fn new(backend: SqliteBackend) -> Self {
        let (tx, rx) = mpsc::channel();
        match std::thread::Builder::new()
            .name("opc-alarm-persist-audit".to_string())
            .spawn(move || run_audit_worker(backend, rx))
        {
            Ok(worker) => Self {
                tx: Some(tx),
                worker: Some(worker),
                startup_error: None,
            },
            Err(err) => Self {
                tx: None,
                worker: None,
                startup_error: Some(format!("failed to spawn audit worker: {err}")),
            },
        }
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

        let event = PersistAuditEvent {
            action: action_str.to_string(),
            outcome: outcome_str.to_string(),
            alarm_id: event.alarm_id.as_str().to_string(),
            alarm_type: event.alarm_type.as_str().to_string(),
            probable_cause: event.probable_cause.to_string(),
            principal: redacted_principal,
            tenant: event.tenant.clone(),
            reason: redacted_reason,
            scope: scope_str,
            correlation_id: redacted_correlation_id,
            occurred_at: occurred_at_str,
        };

        let tx = self.tx.as_ref().ok_or_else(|| {
            self.startup_error
                .clone()
                .unwrap_or_else(|| "audit worker unavailable".to_string())
        })?;
        let (result_tx, result_rx) = mpsc::channel();
        tx.send(AuditAppendRequest { event, result_tx })
            .map_err(|_| "audit worker shut down".to_string())?;
        result_rx
            .recv()
            .map_err(|_| "audit worker stopped before completing append".to_string())?
    }
}

impl Drop for PersistAlarmAuditSink {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run_audit_worker(backend: SqliteBackend, rx: mpsc::Receiver<AuditAppendRequest>) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    match runtime {
        Ok(runtime) => {
            for request in rx {
                let AuditAppendRequest { event, result_tx } = request;
                let result = catch_unwind(AssertUnwindSafe(|| {
                    runtime.block_on(async {
                        backend
                            .record_alarm_audit(
                                &event.action,
                                &event.outcome,
                                &event.alarm_id,
                                &event.alarm_type,
                                &event.probable_cause,
                                &event.principal,
                                event.tenant.as_deref(),
                                &event.reason,
                                &event.scope,
                                event.correlation_id.as_deref(),
                                &event.occurred_at,
                            )
                            .await
                            .map_err(|e| format!("Database audit append failed: {e}"))
                    })
                }))
                .unwrap_or_else(|panic| {
                    Err(format!(
                        "Audit append panicked: {}",
                        panic_reason(panic.as_ref())
                    ))
                });
                let _ = result_tx.send(result);
            }
        }
        Err(err) => {
            let message = format!("failed to build audit runtime: {err}");
            for request in rx {
                let _ = request.result_tx.send(Err(message.clone()));
            }
        }
    }
}

fn panic_reason(panic: &(dyn Any + Send)) -> String {
    panic
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_string())
}

/// Redact audit free-text fields with the shared support-bundle redactor.
fn redact_sensitive_string(input: &str) -> String {
    let mut summary = opc_redaction::RedactionSummary::default();
    opc_redaction::redact_text(input, &mut summary)
}
