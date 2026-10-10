//! Hold real native Normal replies after the durable handler has completed.
use super::*;
use opc_consensus::ConsensusCompatibility;
use opc_session_store::{
    consensus::session_consensus_work_class, scope_scheduler::ScopeWorkClass,
    SessionConsensusRpcFamily, SessionConsensusRpcHandler,
};
use tokio::sync::Semaphore;

#[derive(Debug)]
pub(super) struct NormalReplyHold {
    pub(super) armed: AtomicBool,
    pub(super) entered: Semaphore,
    pub(super) release: Semaphore,
}
impl Default for NormalReplyHold {
    fn default() -> Self {
        Self {
            armed: AtomicBool::new(false),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
        }
    }
}

#[derive(Debug)]
pub(super) struct Handler {
    pub(super) inner: Arc<dyn SessionConsensusRpcHandler>,
    pub(super) hold: Arc<NormalReplyHold>,
}
#[async_trait]
impl SessionConsensusRpcHandler for Handler {
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
        let hold = self.hold.armed.load(Ordering::Acquire)
            && matches!(
                request.family,
                SessionConsensusRpcFamily::ForwardMutation
                    | SessionConsensusRpcFamily::ForwardRosterMutation
            )
            && session_consensus_work_class(&request) == Ok(ScopeWorkClass::Normal);
        let response = self
            .inner
            .handle_with_compatibility(sender, request, compatibility)
            .await;
        if hold && response.result.is_ok() {
            self.hold.entered.add_permits(1);
            self.hold.release.acquire().await.unwrap().forget();
        }
        response
    }
}
