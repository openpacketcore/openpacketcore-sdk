//! Original-operation retention owned by the existing serial ConfigBus worker.
//!
//! There is no secondary admission queue. At most one unsettled encrypted
//! preparation survives between worker messages. Settled entries retain only
//! bounded authenticated handles/receipts; only those entries may be evicted.
//! Authority-side reservations and recovery remain authoritative after restart.

use opc_config_model::RequestId;
use opc_persist::audit_authority::{AuditCaller, AuditOperationHandle};

use super::store::TargetAttempt;

const MAX_RETAINED_ORIGINALS: usize = crate::commit::DEFAULT_COMMIT_QUEUE_CAPACITY;

#[derive(Clone, Copy, PartialEq, Eq)]
struct RequestKey {
    request: RequestId,
    caller: AuditCaller,
}

struct RegisteredTarget {
    // A recovery token does not expose a trusted raw request identity. A fresh
    // worker therefore indexes that retained original by authenticated handle.
    request: Option<RequestKey>,
    attempt: TargetAttempt,
}

pub(super) struct TargetRegistry {
    entries: Vec<RegisteredTarget>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RegistryRefusal {
    /// The raw request must match the originally bound preparation.
    RequestBindingMismatch,
    /// A raw request collision never replaces or re-encrypts the first original.
    DuplicateRequest,
    /// Lookup/completion of the retained original must precede another mutation.
    OriginalUnsettled,
    /// No settled slot can safely be reclaimed.
    Full,
}

impl TargetRegistry {
    pub(super) fn new() -> Self {
        Self {
            entries: Vec::with_capacity(MAX_RETAINED_ORIGINALS),
        }
    }

    // Invoke before provider/model preparation, then check again when retaining
    // the original before admission. Both calls run in the same serial worker.
    pub(super) fn check_new(
        &self,
        request: RequestId,
        caller: AuditCaller,
    ) -> Result<(), RegistryRefusal> {
        let key = RequestKey { request, caller };
        if self.entries.iter().any(|entry| entry.request == Some(key)) {
            return Err(RegistryRefusal::DuplicateRequest);
        }
        self.check_slot()
    }

    pub(super) fn has_unsettled(&self) -> bool {
        self.entries.iter().any(|entry| !Self::reclaimable(entry))
    }

    fn check_slot(&self) -> Result<(), RegistryRefusal> {
        if self.has_unsettled() {
            return Err(RegistryRefusal::OriginalUnsettled);
        }
        Ok(())
    }

    fn reclaimable(entry: &RegisteredTarget) -> bool {
        (entry.attempt.completion_settled() || entry.attempt.admission_refused())
            && !entry.attempt.requires_lock_publication()
    }

    // Return only an opaque bounded handle. The registry owns the complete
    // preparation before execute_target is polled, independently of RPC loss.
    pub(super) fn retain_new(
        &mut self,
        request: RequestId,
        attempt: TargetAttempt,
    ) -> Result<AuditOperationHandle, RegistryRefusal> {
        if attempt.request_id() != Some(request) {
            return Err(RegistryRefusal::RequestBindingMismatch);
        }
        let caller = attempt.caller();
        self.check_new(request, caller)?;
        let handle = attempt.handle().clone();
        self.insert(RegisteredTarget {
            request: Some(RequestKey { request, caller }),
            attempt,
        })?;
        Ok(handle)
    }

    pub(super) fn retain_recovered(
        &mut self,
        attempt: TargetAttempt,
    ) -> Result<AuditOperationHandle, RegistryRefusal> {
        let handle = attempt.handle().clone();
        let caller = attempt.caller();
        if self.original_mut(&handle, caller).is_some() {
            // Never replace cached progress, especially an already known result
            // or acknowledged completion, with an older retained read.
            return Ok(handle);
        }
        self.check_slot()?;
        self.insert(RegisteredTarget {
            request: None,
            attempt,
        })?;
        Ok(handle)
    }

    fn insert(&mut self, entry: RegisteredTarget) -> Result<(), RegistryRefusal> {
        if self.entries.len() >= MAX_RETAINED_ORIGINALS {
            let Some(index) = self.entries.iter().position(Self::reclaimable) else {
                return Err(RegistryRefusal::Full);
            };
            self.entries.remove(index);
        }
        self.entries.push(entry);
        Ok(())
    }

    // caller must be independently projected from current trusted authentication,
    // never copied from a recovery token or numeric protocol session identifier.
    pub(super) fn original_mut(
        &mut self,
        handle: &AuditOperationHandle,
        caller: AuditCaller,
    ) -> Option<&mut TargetAttempt> {
        self.entries
            .iter_mut()
            .find(|entry| entry.attempt.handle() == handle && entry.attempt.caller() == caller)
            .map(|entry| &mut entry.attempt)
    }

    pub(super) fn original_handle(
        &self,
        request: RequestId,
        caller: AuditCaller,
    ) -> Option<AuditOperationHandle> {
        let key = RequestKey { request, caller };
        self.entries
            .iter()
            .find(|entry| entry.request == Some(key))
            .map(|entry| entry.attempt.handle().clone())
    }

    pub(super) async fn recover_unsettled(
        &mut self,
        port: &super::store::NetconfAuditStore,
        sessions: &mut super::session_registry::SessionRegistry,
    ) {
        for entry in &mut self.entries {
            if !Self::reclaimable(entry) {
                let _ = port.recover_target(&mut entry.attempt).await;
                sessions.finalize_lock(port, &mut entry.attempt).await;
            }
        }
    }
}
