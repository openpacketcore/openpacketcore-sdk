//! `opc-runtime` supervision helpers for the NETCONF listener.

use std::sync::Arc;

use opc_config_model::OpcConfig;
use opc_identity::IdentityState;
use opc_mgmt_audit::AuditSink;
use opc_mgmt_authz::PolicySource;
use opc_mgmt_transport::TlsBootstrap;
use opc_runtime::{
    Criticality, RestartPolicy, RuntimeError, ShutdownToken, Supervisor, TaskError, TaskHandle,
    TaskKind, TaskName,
};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::binding::NetconfConfigBinding;
use crate::listener::{run_read_only_tls_listener_shared, TlsListenerConfig};
use crate::server::ReadOnlyNetconfServer;

/// Supervisor metadata and protocol bounds for a NETCONF-over-TLS listener task.
#[derive(Debug, Clone)]
pub struct SupervisedTlsListenerConfig {
    /// Supervisor task name.
    pub task_name: TaskName,
    /// Runtime health impact if the listener fails.
    pub criticality: Criticality,
    /// Restart policy used by `opc-runtime`.
    pub restart: RestartPolicy,
    /// NETCONF listener/session configuration.
    pub listener: TlsListenerConfig,
}

impl Default for SupervisedTlsListenerConfig {
    fn default() -> Self {
        Self {
            task_name: TaskName::new("netconf-tls-listener"),
            criticality: Criticality::Degrade,
            restart: RestartPolicy::default(),
            listener: TlsListenerConfig::default(),
        }
    }
}

/// Spawns the read-only NETCONF-over-TLS listener under `opc-runtime`.
///
/// The caller supplies the runtime shutdown token, normally the token passed to
/// the CNF initialization hook by `opc-runtime::Builder`. The listener is
/// registered as [`TaskKind::Listener`] and uses the same fail-closed TLS,
/// session, audit, NACM, and metrics paths as [`crate::run_read_only_tls_listener`].
pub async fn spawn_read_only_tls_listener<C, B, P, A>(
    supervisor: &Supervisor,
    server: Arc<ReadOnlyNetconfServer<C, B, P, A>>,
    listener: TcpListener,
    tls: TlsBootstrap,
    identity_rx: watch::Receiver<Option<IdentityState>>,
    shutdown: ShutdownToken,
    config: SupervisedTlsListenerConfig,
) -> Result<TaskHandle, RuntimeError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C> + 'static,
    P: PolicySource + 'static,
    A: AuditSink + 'static,
{
    let listener = Arc::new(listener);
    let task_name = config.task_name.clone();
    let failure_label = task_name.to_string();
    let listener_config = config.listener;

    supervisor
        .spawn(
            task_name,
            TaskKind::Listener,
            config.criticality,
            config.restart,
            move || {
                let server = Arc::clone(&server);
                let listener = Arc::clone(&listener);
                let tls = tls.clone();
                let identity_rx = identity_rx.clone();
                let shutdown = shutdown.clone();
                let failure_label = failure_label.clone();
                Box::pin(async move {
                    run_read_only_tls_listener_shared(
                        server,
                        listener,
                        tls,
                        identity_rx,
                        shutdown,
                        listener_config,
                    )
                    .await
                    .map(|result| {
                        tracing::debug!(
                            accepted_sessions = result.accepted_sessions,
                            completed_sessions = result.completed_sessions,
                            failed_sessions = result.failed_sessions,
                            rejected_sessions = result.rejected_sessions,
                            "supervised NETCONF TLS listener stopped"
                        );
                    })
                    .map_err(|err| TaskError::Failed(failure_label, Arc::new(err)))
                })
            },
        )
        .await
}
