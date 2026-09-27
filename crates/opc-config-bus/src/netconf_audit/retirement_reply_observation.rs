//! One-shot observation after the real native retirement reply, before retention.
//! This module is compiled only for unit tests. It supplies no result.
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc, Mutex, Weak,
};

use tokio::sync::Notify;

use super::{AuditOperationHandle, AuditOperationReceipt, AuditOperationState, NetconfAuditStore};

#[derive(Default)]
pub(super) struct ReplySlot {
    waiting: Mutex<Option<Weak<ReplyState>>>,
}

struct ReplyState {
    handle: AuditOperationHandle,
    // 0: armed; 1: actual reply held; 2: cancelled; 3: released normally.
    phase: AtomicU8,
    entered: Notify,
    release: Notify,
}

pub(in crate::netconf_audit) struct RetirementReplyGate(Arc<ReplyState>);

impl NetconfAuditStore {
    pub(in crate::netconf_audit) fn hold_retirement_reply(
        &self,
        handle: &AuditOperationHandle,
    ) -> RetirementReplyGate {
        let state = Arc::new(ReplyState {
            handle: handle.clone(),
            phase: AtomicU8::new(0),
            entered: Notify::new(),
            release: Notify::new(),
        });
        let mut waiting = self.inner.retirement_reply.waiting.lock().unwrap();
        assert!(
            waiting.as_ref().and_then(Weak::upgrade).is_none(),
            "only one retirement reply gate may be armed per authority"
        );
        *waiting = Some(Arc::downgrade(&state));
        RetirementReplyGate(state)
    }
}

impl ReplySlot {
    pub(super) async fn hold(
        &self,
        handle: &AuditOperationHandle,
        receipt: &AuditOperationReceipt,
    ) {
        // The public SDK has already executed the actual retirement and
        // authenticated its native result. Definite refusal and Unknown cannot
        // enter this gate, and no test callback can manufacture the receipt.
        if receipt.handle() != handle
            || receipt.state() != AuditOperationState::Rejected
            || receipt.terminal_recorded()
        {
            return;
        }
        let state = {
            let mut waiting = self.waiting.lock().unwrap();
            let Some(state) = waiting.as_ref().and_then(Weak::upgrade) else {
                return;
            };
            if &state.handle != handle {
                return;
            }
            // Consume before awaiting, so an original's recovery never reuses
            // the gate and no mutex or queued payload crosses the await.
            waiting.take();
            state
        };
        let mut held = HeldReply {
            state: Arc::clone(&state),
            released: false,
        };
        state.phase.store(1, Ordering::Release);
        state.entered.notify_one();
        state.release.notified().await;
        held.released = true;
    }
}

struct HeldReply {
    state: Arc<ReplyState>,
    released: bool,
}

impl Drop for HeldReply {
    fn drop(&mut self) {
        self.state
            .phase
            .store(if self.released { 3 } else { 2 }, Ordering::Release);
    }
}

impl RetirementReplyGate {
    pub(in crate::netconf_audit) async fn entered(&self) {
        if self.0.phase.load(Ordering::Acquire) == 0 {
            self.0.entered.notified().await;
        }
    }

    pub(in crate::netconf_audit) fn was_cancelled(&self) -> bool {
        self.0.phase.load(Ordering::Acquire) == 2
    }
}

impl Drop for RetirementReplyGate {
    fn drop(&mut self) {
        // A failing assertion also releases any still-owned reply future.
        self.0.release.notify_one();
    }
}
