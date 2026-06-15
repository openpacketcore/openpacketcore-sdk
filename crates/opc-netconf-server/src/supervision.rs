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
use crate::ssh::{
    run_read_only_ssh_call_home, run_read_only_ssh_listener_shared, SshCallHomeConfig,
    SshListenerConfig,
};

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

/// Supervisor metadata and protocol bounds for a NETCONF-over-SSH listener task.
#[derive(Debug, Clone)]
pub struct SupervisedSshListenerConfig {
    /// Supervisor task name.
    pub task_name: TaskName,
    /// Runtime health impact if the listener fails.
    pub criticality: Criticality,
    /// Restart policy used by `opc-runtime`.
    pub restart: RestartPolicy,
    /// NETCONF-over-SSH listener/session configuration.
    pub listener: SshListenerConfig,
}

/// Supervisor metadata and protocol bounds for a NETCONF-over-SSH Call Home task.
#[derive(Debug, Clone)]
pub struct SupervisedSshCallHomeConfig {
    /// Supervisor task name.
    pub task_name: TaskName,
    /// Runtime health impact if the Call Home loop fails before shutdown.
    pub criticality: Criticality,
    /// Restart policy used by `opc-runtime`.
    pub restart: RestartPolicy,
    /// NETCONF-over-SSH Call Home configuration.
    pub call_home: SshCallHomeConfig,
}

/// Spawns the NETCONF-over-SSH listener under `opc-runtime`.
///
/// Host keys, authorized client keys, tenancy, SSH authentication policy, and
/// NETCONF session bounds are all supplied by the caller through
/// [`SshListenerConfig`]. The listener is registered as [`TaskKind::Listener`]
/// and uses the same fail-closed NETCONF session, NACM, audit, metrics, and
/// drain paths as [`crate::run_read_only_ssh_listener`].
pub async fn spawn_read_only_ssh_listener<C, B, P, A>(
    supervisor: &Supervisor,
    server: Arc<ReadOnlyNetconfServer<C, B, P, A>>,
    listener: TcpListener,
    shutdown: ShutdownToken,
    config: SupervisedSshListenerConfig,
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
                let shutdown = shutdown.clone();
                let listener_config = listener_config.clone();
                let failure_label = failure_label.clone();
                Box::pin(async move {
                    run_read_only_ssh_listener_shared(server, listener, shutdown, listener_config)
                        .await
                        .map(|result| {
                            tracing::debug!(
                                accepted_sessions = result.accepted_sessions,
                                completed_sessions = result.completed_sessions,
                                failed_sessions = result.failed_sessions,
                                rejected_sessions = result.rejected_sessions,
                                "supervised NETCONF SSH listener stopped"
                            );
                        })
                        .map_err(|err| TaskError::Failed(failure_label, Arc::new(err)))
                })
            },
        )
        .await
}

/// Spawns the NETCONF-over-SSH Call Home loop under `opc-runtime`.
///
/// The task initiates outbound TCP connections to configured NMS endpoints but
/// still runs the SSH server role after the socket is connected. The same
/// public-key auth, NACM, audit, metrics, NETCONF session, and shutdown-drain
/// paths are used as the inbound SSH listener.
pub async fn spawn_read_only_ssh_call_home<C, B, P, A>(
    supervisor: &Supervisor,
    server: Arc<ReadOnlyNetconfServer<C, B, P, A>>,
    shutdown: ShutdownToken,
    config: SupervisedSshCallHomeConfig,
) -> Result<TaskHandle, RuntimeError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C> + 'static,
    P: PolicySource + 'static,
    A: AuditSink + 'static,
{
    let task_name = config.task_name.clone();
    let failure_label = task_name.to_string();
    let call_home_config = config.call_home;

    supervisor
        .spawn(
            task_name,
            TaskKind::Listener,
            config.criticality,
            config.restart,
            move || {
                let server = Arc::clone(&server);
                let shutdown = shutdown.clone();
                let call_home_config = call_home_config.clone();
                let failure_label = failure_label.clone();
                Box::pin(async move {
                    run_read_only_ssh_call_home(server, shutdown, call_home_config)
                        .await
                        .map(|result| {
                            tracing::debug!(
                                connection_attempts = result.connection_attempts,
                                connected_sessions = result.connected_sessions,
                                completed_sessions = result.completed_sessions,
                                connection_failures = result.connection_failures,
                                failed_sessions = result.failed_sessions,
                                rejected_sessions = result.rejected_sessions,
                                "supervised NETCONF SSH Call Home stopped"
                            );
                        })
                        .map_err(|err| TaskError::Failed(failure_label, Arc::new(err)))
                })
            },
        )
        .await
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
