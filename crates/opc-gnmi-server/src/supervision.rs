//! `opc-runtime` supervision helpers for the gNMI listener.

use std::sync::Arc;

use opc_config_model::OpcConfig;
use opc_identity::IdentityState;
use opc_mgmt_transport::TlsBootstrap;
use opc_runtime::{
    Criticality, RestartPolicy, RuntimeError, ShutdownToken, Supervisor, TaskError, TaskHandle,
    TaskKind, TaskName,
};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::listener::{run_gnmi_tls_listener_shared, GnmiListenerConfig};
use crate::{GnmiConfigBinding, GnmiServer};

/// Supervisor metadata and protocol bounds for a gNMI-over-TLS listener task.
#[derive(Debug, Clone)]
pub struct SupervisedGnmiTlsListenerConfig {
    /// Supervisor task name.
    pub task_name: TaskName,
    /// Runtime health impact if the listener fails.
    pub criticality: Criticality,
    /// Restart policy used by `opc-runtime`.
    pub restart: RestartPolicy,
    /// gNMI listener/session configuration.
    pub listener: GnmiListenerConfig,
}

impl Default for SupervisedGnmiTlsListenerConfig {
    fn default() -> Self {
        Self {
            task_name: TaskName::new("gnmi-tls-listener"),
            criticality: Criticality::Degrade,
            restart: RestartPolicy::default(),
            listener: GnmiListenerConfig::default(),
        }
    }
}

/// Spawns the gNMI-over-TLS listener under `opc-runtime`.
///
/// The caller supplies the runtime shutdown token, normally the same token
/// owned by the CNF supervisor. The listener is registered as
/// [`TaskKind::Listener`] and uses the same fail-closed TLS, SPIFFE principal,
/// NACM, audit, metrics, and drain paths as [`crate::run_gnmi_tls_listener`].
pub async fn spawn_gnmi_tls_listener<C, B>(
    supervisor: &Supervisor,
    server: Arc<GnmiServer<C, B>>,
    listener: TcpListener,
    tls: TlsBootstrap,
    identity_rx: watch::Receiver<Option<IdentityState>>,
    shutdown: ShutdownToken,
    config: SupervisedGnmiTlsListenerConfig,
) -> Result<TaskHandle, RuntimeError>
where
    C: OpcConfig + 'static,
    B: GnmiConfigBinding<C> + 'static,
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
                    run_gnmi_tls_listener_shared(
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
                            accepted_connections = result.accepted_connections,
                            rejected_connections = result.rejected_connections,
                            failed_connections = result.failed_connections,
                            "supervised gNMI TLS listener stopped"
                        );
                    })
                    .map_err(|err| TaskError::Failed(failure_label, Arc::new(err)))
                })
            },
        )
        .await
}
