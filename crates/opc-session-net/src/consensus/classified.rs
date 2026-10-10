//! Five independent voter transport pools and pre-TLS listener capacities.
use super::*;
use opc_session_store::consensus::session_consensus_work_class;
use opc_session_store::scope_scheduler::ScopeWorkClass;

pub(super) struct ClassTransport {
    pub(super) target: ConsensusTarget,
    pub(super) pool: Arc<ConsensusConnectionPool>,
    pub(super) tls_config: Option<opc_tls::AuthenticatedClientConfig>,
}
pub(super) fn class_index(class: ScopeWorkClass) -> Result<usize, SessionConsensusPeerError> {
    match class {
        ScopeWorkClass::SafetyControl => Ok(0),
        ScopeWorkClass::Emergency => Ok(1),
        ScopeWorkClass::EmergencyClassification => Ok(2),
        ScopeWorkClass::Normal => Ok(3),
        ScopeWorkClass::Maintenance => Ok(4),
        _ => Err(SessionConsensusPeerError::Protocol),
    }
}

impl RemoteSessionConsensusPeer {
    /// Select five separately resolved class endpoints in
    /// SafetyControl/Emergency/classification/Normal/Maintenance order.
    /// Every resolver retains the peer's existing exact membership binding.
    #[must_use]
    pub fn with_class_resolvers(mut self, resolvers: [RemoteAddrResolver; 5]) -> Self {
        self.class_transports = Some(Arc::new(resolvers.map(|resolver| {
            ClassTransport {
                target: ConsensusTarget::resolved(&self.binding, resolver),
                pool: Arc::new(ConsensusConnectionPool::new(self.lifecycle_policy)),
                tls_config: self
                    .tls_config
                    .clone()
                    .map(opc_tls::AuthenticatedClientConfig::with_independent_handshake_budget),
            }
        })));
        self
    }
    pub(super) fn reset_class_pools(&mut self) {
        if let Some(transports) = &self.class_transports {
            self.class_transports = Some(Arc::new(std::array::from_fn(|index| ClassTransport {
                target: transports[index].target.clone(),
                pool: Arc::new(ConsensusConnectionPool::new(self.lifecycle_policy)),
                tls_config: transports[index].tls_config.clone(),
            })));
        }
    }
}
impl SessionConsensusServer {
    /// Bind independent class listeners with separate connection, handshake,
    /// execution and reply capacity. A wrong-class request is refused.
    pub async fn listen_classified(
        self,
        addresses: [SocketAddr; 5],
    ) -> io::Result<ClassifiedSessionConsensusServerHandle> {
        self.validate_listener_configuration()?;
        let mut result = ClassifiedSessionConsensusServerHandle {
            addresses,
            handles: Vec::with_capacity(5),
        };
        let classes = [
            ScopeWorkClass::SafetyControl,
            ScopeWorkClass::Emergency,
            ScopeWorkClass::EmergencyClassification,
            ScopeWorkClass::Normal,
            ScopeWorkClass::Maintenance,
        ];
        for (index, class) in classes.into_iter().enumerate() {
            let endpoint = Self {
                handler: Arc::new(ClassHandler {
                    class,
                    inner: self.handler.clone(),
                }),
                tls_config: self
                    .tls_config
                    .clone()
                    .map(opc_tls::AuthenticatedServerConfig::with_independent_handshake_budget),
                membership: self.membership.clone(),
                max_connections: self.max_connections,
                max_frame_size: self.max_frame_size,
                idle_timeout: self.idle_timeout,
                rpc_timeout: self.rpc_timeout,
                lifecycle_policy: self.lifecycle_policy,
                reauthentication: self.reauthentication.clone(),
                #[cfg(test)]
                post_accept_setup_hook: self.post_accept_setup_hook.clone(),
            };
            let (handle, address) = endpoint.listen(addresses[index]).await?;
            result.addresses[index] = address;
            result.handles.push(handle);
        }
        Ok(result)
    }
}
#[derive(Debug)]
struct ClassHandler {
    class: ScopeWorkClass,
    inner: Arc<dyn SessionConsensusRpcHandler>,
}
#[async_trait]
impl SessionConsensusRpcHandler for ClassHandler {
    fn compatibility(&self) -> Option<ConsensusCompatibility> {
        self.inner.compatibility()
    }
    async fn handle(
        &self,
        sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        self.handle_with_compatibility(sender, request, None).await
    }
    async fn handle_with_compatibility(
        &self,
        sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
        compatibility: Option<ConsensusCompatibility>,
    ) -> SessionConsensusWireResponse {
        if session_consensus_work_class(&request) != Ok(self.class) {
            return SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::Protocol),
            };
        }
        self.inner
            .handle_with_compatibility(sender, request, compatibility)
            .await
    }
}
/// Supervision of all five class-specific voter listeners.
pub struct ClassifiedSessionConsensusServerHandle {
    addresses: [SocketAddr; 5],
    handles: Vec<SessionConsensusServerHandle>,
}
impl ClassifiedSessionConsensusServerHandle {
    /// Bound addresses in the fixed class order.
    pub const fn addresses(&self) -> [SocketAddr; 5] {
        self.addresses
    }
    /// Cancel and join every listener and connection; accepted native consensus
    /// work remains supervised by the original store execution permits.
    pub async fn abort_and_wait(mut self) {
        for handle in self.handles.drain(..) {
            handle.abort_and_wait().await;
        }
    }
}
impl Drop for ClassifiedSessionConsensusServerHandle {
    fn drop(&mut self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}
