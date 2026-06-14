//! NETCONF-over-TLS TCP listener.
//!
//! This module owns only the accept loop. TLS policy is built through
//! `opc-mgmt-transport`, principal extraction stays in [`crate::transport`], and
//! NETCONF protocol sequencing stays in [`crate::session`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use opc_config_model::OpcConfig;
use opc_identity::IdentityState;
use opc_mgmt_audit::AuditSink;
use opc_mgmt_authz::PolicySource;
use opc_mgmt_limits::LimitsError;
use opc_mgmt_transport::{TlsBootstrap, TransportError};
use opc_runtime::ShutdownToken;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore, TryAcquireError};
use tokio::task::{JoinError, JoinSet};
use tokio_rustls::TlsAcceptor;

use crate::binding::NetconfConfigBinding;
use crate::metrics::{active_session, TRANSPORT_NETCONF_TLS};
use crate::server::ReadOnlyNetconfServer;
use crate::session::SessionConfig;
use crate::transport::{run_read_only_tls_session, TlsSessionError};

/// Runtime configuration for the NETCONF-over-TLS listener.
#[derive(Debug, Clone, Copy)]
pub struct TlsListenerConfig {
    /// Per-session protocol bounds and frame timeout.
    pub session: SessionConfig,
    /// First NETCONF session id assigned by this listener instance.
    pub first_session_id: u64,
    /// Maximum time to wait for in-flight sessions after shutdown begins.
    pub drain_timeout: Duration,
}

impl Default for TlsListenerConfig {
    fn default() -> Self {
        Self {
            session: SessionConfig::default(),
            first_session_id: 1,
            drain_timeout: Duration::from_secs(30),
        }
    }
}

/// Summary returned when the listener stops.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TlsListenerResult {
    /// Sessions accepted and handed to a TLS/session worker.
    pub accepted_sessions: u64,
    /// Sessions that exited cleanly.
    pub completed_sessions: u64,
    /// Sessions whose TLS handshake, NETCONF loop, join, or forced drain failed.
    pub failed_sessions: u64,
    /// Connections rejected because [`opc_mgmt_limits::MgmtLimits::max_sessions`]
    /// was already reached.
    pub rejected_sessions: u64,
}

/// Listener-level failure before the accept loop can run.
#[derive(Debug, Error)]
pub enum TlsListenerError {
    /// Management-plane limits were invalid.
    #[error(transparent)]
    Limit(#[from] LimitsError),
    /// TLS bootstrap failed, usually due to fail-closed peer-policy rejection.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// TCP accept failed.
    #[error("NETCONF TLS listener I/O error")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Error)]
enum WorkerError {
    #[error("NETCONF TLS accept failed")]
    TlsAccept(#[source] std::io::Error),
    #[error(transparent)]
    Session(#[from] TlsSessionError),
}

/// Runs a NETCONF-over-TLS listener until shutdown is requested.
///
/// The listener stops accepting new sessions as soon as `shutdown` fires. Each
/// accepted connection is checked against `config.session.limits.max_sessions`.
/// Over-limit connections are dropped without parsing any peer input. This
/// function is suitable for a CNF to spawn under `opc-runtime::Supervisor` as a
/// `TaskKind::Listener`; the explicit [`ShutdownToken`] keeps the accept loop
/// independently testable.
pub async fn run_read_only_tls_listener<C, B, P, A>(
    server: Arc<ReadOnlyNetconfServer<C, B, P, A>>,
    listener: TcpListener,
    tls: TlsBootstrap,
    identity_rx: watch::Receiver<Option<IdentityState>>,
    shutdown: ShutdownToken,
    config: TlsListenerConfig,
) -> Result<TlsListenerResult, TlsListenerError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C> + 'static,
    P: PolicySource + 'static,
    A: AuditSink + 'static,
{
    run_read_only_tls_listener_shared(
        server,
        Arc::new(listener),
        tls,
        identity_rx,
        shutdown,
        config,
    )
    .await
}

pub(crate) async fn run_read_only_tls_listener_shared<C, B, P, A>(
    server: Arc<ReadOnlyNetconfServer<C, B, P, A>>,
    listener: Arc<TcpListener>,
    tls: TlsBootstrap,
    identity_rx: watch::Receiver<Option<IdentityState>>,
    shutdown: ShutdownToken,
    config: TlsListenerConfig,
) -> Result<TlsListenerResult, TlsListenerError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C> + 'static,
    P: PolicySource + 'static,
    A: AuditSink + 'static,
{
    config.session.limits.validate()?;
    let tls_config = Arc::new(tls.build_server_config(identity_rx.clone())?);
    let acceptor = TlsAcceptor::from(tls_config);
    let semaphore = Arc::new(Semaphore::new(config.session.limits.max_sessions));
    let next_session_id = Arc::new(AtomicU64::new(config.first_session_id));
    let mut workers = JoinSet::new();
    let mut result = TlsListenerResult::default();

    loop {
        tokio::select! {
            _ = shutdown.shutdown_acknowledged() => {
                break;
            }
            joined = workers.join_next(), if !workers.is_empty() => {
                if let Some(joined) = joined {
                    record_worker_result(joined, &mut result);
                }
            }
            accepted = listener.accept() => {
                let (stream, _peer) = accepted?;
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(TryAcquireError::NoPermits) => {
                        result.rejected_sessions = result.rejected_sessions.saturating_add(1);
                        tracing::debug!(
                            transport = TRANSPORT_NETCONF_TLS,
                            "NETCONF session rejected because max_sessions is reached"
                        );
                        continue;
                    }
                    Err(TryAcquireError::Closed) => break,
                };

                let server = Arc::clone(&server);
                let acceptor = acceptor.clone();
                let identity_rx = identity_rx.clone();
                let session_config = config.session;
                let session_id = next_session_id.fetch_add(1, Ordering::Relaxed);
                result.accepted_sessions = result.accepted_sessions.saturating_add(1);

                workers.spawn(async move {
                    let _permit = permit;
                    let _active_session = active_session(TRANSPORT_NETCONF_TLS);
                    let mut stream = acceptor
                        .accept(stream)
                        .await
                        .map_err(WorkerError::TlsAccept)?;
                    run_read_only_tls_session(
                        server.as_ref(),
                        &mut stream,
                        &identity_rx,
                        session_config,
                        session_id,
                    )
                    .await?;
                    Ok::<(), WorkerError>(())
                });
            }
        }
    }

    drain_workers(&mut workers, config.drain_timeout, &mut result).await;
    Ok(result)
}

async fn drain_workers(
    workers: &mut JoinSet<Result<(), WorkerError>>,
    timeout: Duration,
    result: &mut TlsListenerResult,
) {
    let drain = async {
        while let Some(joined) = workers.join_next().await {
            record_worker_result(joined, result);
        }
    };

    if tokio::time::timeout(timeout, drain).await.is_err() {
        result.failed_sessions = result
            .failed_sessions
            .saturating_add(workers.len().try_into().unwrap_or(u64::MAX));
        workers.abort_all();
        while workers.join_next().await.is_some() {}
    }
}

fn record_worker_result(
    joined: Result<Result<(), WorkerError>, JoinError>,
    result: &mut TlsListenerResult,
) {
    match joined {
        Ok(Ok(())) => {
            result.completed_sessions = result.completed_sessions.saturating_add(1);
        }
        Ok(Err(_)) | Err(_) => {
            result.failed_sessions = result.failed_sessions.saturating_add(1);
        }
    }
}
