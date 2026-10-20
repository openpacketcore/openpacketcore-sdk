//! Connection attribution available only to non-production qualification builds.

use std::cell::RefCell;
use std::future::Future;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use opc_redaction::metrics::METRICS;
use opc_session_store::SessionConsensusNodeId;
use serde::{Deserialize, Serialize};

/// Prefix for one complete JSON connection outcome in a child's stderr.
pub const TRANSPORT_FAILURE_PREFIX: &str = "qualification_transport_failure ";

/// One counted failure, with no application payload or credential material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionFailure {
    /// Process identity distinguishes restarted children.
    pub process_id: u32,
    /// Exact value of the transport counter after this outcome.
    pub counter: u64,
    /// Process-local connection/attempt identity.
    pub connection_id: u64,
    /// Consensus/direct and inbound/outbound origin.
    pub origin: String,
    /// Last operation attempted on this connection.
    pub stage: String,
    /// Existing typed result responsible for the counter increment.
    pub outcome: String,
    /// Closed standard I/O error category, when available.
    pub io_kind: Option<String>,
    /// Local TCP endpoint, if a socket was allocated.
    pub local_addr: Option<SocketAddr>,
    /// Remote TCP endpoint, if resolved or accepted.
    pub peer_addr: Option<SocketAddr>,
    /// Locally bound consensus voter, if known.
    pub local_node: Option<SessionConsensusNodeId>,
    /// Authenticated or configured remote voter, if known.
    pub remote_node: Option<SessionConsensusNodeId>,
    /// Explicit reauthentication generation at connection setup.
    pub generation: Option<u64>,
    /// TLS material publication epoch at connection setup.
    pub material_epoch: Option<u64>,
}

tokio::task_local! {
    static CONNECTION: RefCell<ConnectionFailure>;
}

static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);
static TRANSPORT_COUNTER_WRITERS: Mutex<()> = Mutex::new(());

pub(crate) fn context(
    origin: &str,
    local_node: Option<SessionConsensusNodeId>,
    remote_node: Option<SessionConsensusNodeId>,
    generation: u64,
    material_epoch: Option<opc_tls::TlsMaterialEpoch>,
) -> ConnectionFailure {
    ConnectionFailure {
        process_id: std::process::id(),
        counter: 0,
        connection_id: NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed),
        origin: origin.to_owned(),
        stage: "admission".to_owned(),
        outcome: String::new(),
        io_kind: None,
        local_addr: None,
        peer_addr: None,
        local_node,
        remote_node,
        generation: Some(generation),
        material_epoch: material_epoch.map(opc_tls::TlsMaterialEpoch::get),
    }
}

pub(crate) async fn scope<F: Future>(context: ConnectionFailure, future: F) -> F::Output {
    CONNECTION.scope(RefCell::new(context), future).await
}

pub(crate) fn update(update: impl FnOnce(&mut ConnectionFailure)) {
    let _ = CONNECTION.try_with(|context| update(&mut context.borrow_mut()));
}

pub(crate) fn stage(stage: &str) {
    update(|context| {
        context.stage.clear();
        context.stage.push_str(stage);
        context.io_kind = None;
    });
}

pub(crate) fn begin_resolution(material_epoch: Option<opc_tls::TlsMaterialEpoch>) {
    stage("resolve");
    update(|context| {
        // A TLS material retry may allocate another socket inside one logical
        // attempt. A failed new lookup must never name the previous socket.
        context.local_addr = None;
        context.peer_addr = None;
        context.material_epoch = material_epoch.map(opc_tls::TlsMaterialEpoch::get);
    });
}

pub(crate) fn socket(stream: &tokio::net::TcpStream) {
    update(|context| {
        context.local_addr = stream.local_addr().ok();
        context.peer_addr = stream.peer_addr().ok();
    });
}

pub(crate) fn io_error(error: &io::Error) {
    update(|context| context.io_kind = Some(format!("{:?}", error.kind())));
}

pub(crate) fn record_transport_failure(outcome: &str, io_kind: Option<io::ErrorKind>) {
    // Serialize counter writers and emit before making the increment visible:
    // a parent's sampled counter can never outrun its corresponding stderr line.
    let _guard = TRANSPORT_COUNTER_WRITERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut event = CONNECTION
        .try_with(|context| context.borrow().clone())
        .unwrap_or_else(|_| {
            let mut missing = context("unscoped", None, None, 0, None);
            missing.connection_id = 0;
            missing
        });
    event.counter = METRICS
        .session_net_connection_failure_transport
        .load(Ordering::Relaxed)
        .wrapping_add(1);
    event.outcome = outcome.to_owned();
    if let Some(kind) = io_kind {
        event.io_kind = Some(format!("{kind:?}"));
    }
    if let Ok(json) = serde_json::to_vec(&event) {
        let mut line = TRANSPORT_FAILURE_PREFIX.as_bytes().to_vec();
        line.extend_from_slice(&json);
        line.push(b'\n');
        // A failed write cannot replace the original typed result.
        let _ = io::stderr().lock().write_all(&line);
    }
    METRICS
        .session_net_connection_failure_transport
        .fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn retry_resolution_cannot_attribute_a_failure_to_the_previous_socket() {
        let mut previous = context("consensus-outbound", None, None, 3, None);
        previous.local_addr = Some("127.0.0.1:4000".parse().expect("local endpoint"));
        previous.peer_addr = Some("127.0.0.1:5000".parse().expect("peer endpoint"));
        previous.material_epoch = Some(7);
        previous.io_kind = Some("ConnectionReset".to_owned());
        scope(previous, async {
            begin_resolution(None);
            io_error(&io::Error::from(io::ErrorKind::NotFound));
            CONNECTION.with(|context| {
                let current = context.borrow();
                assert_eq!(current.stage, "resolve");
                assert_eq!(current.io_kind.as_deref(), Some("NotFound"));
                assert_eq!(current.local_addr, None);
                assert_eq!(current.peer_addr, None);
                assert_eq!(current.material_epoch, None);
                assert_eq!(current.generation, Some(3));
            });
        })
        .await;
    }
}
