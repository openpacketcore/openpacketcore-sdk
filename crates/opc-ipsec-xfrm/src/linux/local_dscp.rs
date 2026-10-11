//! DSCP structural work leaves the XFRM actor available to service cleanup.

use super::*;
use opc_local_kernel_lifecycle::{LocalInstalledGraph, LocalScopeResetReceipt};
use std::sync::Mutex;
use tokio::sync::oneshot;

type Reply = Arc<Mutex<Option<oneshot::Sender<Result<Vec<LocalInstalledGraph>, XfrmError>>>>>;
fn closed(reply: &Reply) -> bool {
    reply
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .is_none_or(oneshot::Sender::is_closed)
}
fn send(reply: &Reply, result: Result<Vec<LocalInstalledGraph>, XfrmError>) {
    if let Some(reply) = reply
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    {
        let _ = reply.send(result);
    }
}
fn uncertain() -> XfrmError {
    XfrmError::StateIndeterminate {
        operation: "local_scope_dscp_rebuild",
    }
}
impl LinuxXfrmBackend {
    pub(crate) fn clear_scoped_dscp_activation(&self) {
        self.inner
            .dscp_activation_ready
            .store(false, Ordering::Release);
    }
    pub(crate) fn start_scoped_dscp_rebuild(
        &self,
        reset: LocalScopeResetReceipt,
        reply: oneshot::Sender<Result<Vec<LocalInstalledGraph>, XfrmError>>,
    ) {
        let backend = self.clone();
        let reply = Arc::new(Mutex::new(Some(reply)));
        let worker_reply = reply.clone();
        let started = std::thread::Builder::new()
            .name("opc-scoped-dscp".to_owned())
            .spawn(move || {
                use futures_util::FutureExt;
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(_) => {
                        send(&worker_reply, Err(uncertain()));
                        return;
                    }
                };
                let result = runtime.block_on(async {
                    std::panic::AssertUnwindSafe(backend.rebuild_scoped_dscp(&reset, &worker_reply))
                        .catch_unwind()
                        .await
                        .unwrap_or_else(|_| Err(uncertain()))
                });
                send(&worker_reply, result);
            });
        if started.is_err() {
            send(&reply, Err(uncertain()));
        }
    }
    async fn rebuild_scoped_dscp(
        &self,
        reset: &LocalScopeResetReceipt,
        reply: &Reply,
    ) -> Result<Vec<LocalInstalledGraph>, XfrmError> {
        self.ensure_namespace_binding()?;
        let lifecycle = self.local_lifecycle().ok_or_else(uncertain)?;
        let config = self
            .inner
            .dscp_config
            .as_ref()
            .ok_or(XfrmError::UnsupportedFeature {
                feature: "fixed_outer_dscp",
            })?;
        let relative = config
            .bpffs_pin_root
            .strip_prefix(lifecycle.local_scope().spec().pin_root())
            .map_err(|_| uncertain())?;
        let mut graphs = Vec::new();
        for interface in &config.egress_interfaces {
            self.ensure_namespace_binding()?;
            if closed(reply) {
                return Err(uncertain());
            }
            let ifindex =
                opc_linux_gtpu_sys::ifindex_by_name(interface).map_err(|_| uncertain())?;
            if let Some(ready) = self
                .inner
                .dscp_runtime
                .scoped_graph(reset, config, ifindex)?
            {
                graphs.push(ready);
                continue;
            }
            let graph = crate::XfrmDscpLocalGraph::new(
                relative.join(interface),
                ifindex,
                config.tc_priority,
            )?;
            let binding = lifecycle
                .bind_graph(graph.artifact())
                .map_err(|_| uncertain())?;
            let guard = binding
                .begin_rebuild(reset)
                .await
                .map_err(|_| uncertain())?;
            let loader = self.inner.dscp_runtime.clone();
            let config = config.clone();
            let reply = reply.clone();
            let ready = guard
                .supervise(move |guard, observer_closed| {
                    loader
                        .build_scoped_graph(guard, &config, &|| observer_closed() || closed(&reply))
                })
                .await
                .map_err(|_| uncertain())?;
            graphs.push(ready);
        }
        // No outer read barrier is held while acquiring individual build
        // barriers: a queued reset writer must never deadlock this worker.
        // At final publication one epoch guard covers all graph readbacks.
        let operation = graphs
            .first()
            .ok_or_else(uncertain)?
            .begin_operation()
            .await
            .map_err(|_| uncertain())?;
        for graph in &graphs {
            if !graph.matches_reset(reset) {
                return Err(uncertain());
            }
            graph.recheck().map_err(|_| uncertain())?;
        }
        self.inner.dscp_runtime.ensure_ready(config)?;
        operation.recheck().map_err(|_| uncertain())?;
        if closed(reply) {
            return Err(uncertain());
        }
        self.publish_dscp_activation();
        Ok(graphs)
    }
}
