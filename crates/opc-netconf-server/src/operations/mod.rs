//! NETCONF operation handlers.

use std::future::Future;

use futures_util::FutureExt;
use opc_mgmt_audit::{AuditError, AuditEvent, AuditSink};

pub mod get;
pub mod get_config;
pub mod get_data;

#[derive(Clone, Copy)]
pub(crate) enum AuditMode {
    Synchronous,
    Asynchronous,
}

pub(crate) async fn record_audit<A: AuditSink>(
    mode: AuditMode,
    audit: &A,
    event: &AuditEvent,
) -> Result<(), AuditError> {
    match mode {
        AuditMode::Synchronous => audit.record(event),
        AuditMode::Asynchronous => audit.record_async(event).await,
    }
}

pub(crate) fn poll_ready<F: Future>(future: F) -> F::Output {
    match future.now_or_never() {
        Some(output) => output,
        None => unreachable!("synchronous NETCONF audit path unexpectedly yielded"),
    }
}
