//! Actor-side scoped Child-SA rekey successor: admission, supervised service,
//! progress and readback.
//!
//! The successor effect is a distinct committed activation. Its install keeps
//! the predecessor receipt's flow alive, moves the single protective policy to
//! the successor SA, publishes through the same actor supervisor as ordinary
//! installs, and only then exposes the successor receipt. The predecessor
//! receipt keeps its SA until the caller retires it; only the predecessor SA is
//! removed then, never the policy the successor owns.

#[cfg(test)]
use super::operations::TestFault;
#[cfg(test)]
use std::sync::atomic::Ordering;
use std::sync::Arc;

use futures_util::FutureExt;
use opc_local_kernel_lifecycle::{
    CleanupAttempt, CleanupSchedule, CommittedScopeEffect, LocalEffectUse, LocalOperation,
};
use tokio::sync::oneshot;

use super::effect::Readback;
use super::operations::{
    Operations, ReceiptRole, ScopedXfrmReceipt, ScopedXfrmSuccessorStatus, SuccessorEntry,
    SuccessorInstall, SuccessorLink, PREDECESSOR_RETIRED, SUCCESSOR_PUBLISHED,
    SUCCESSOR_SA_INSTALLED, SUCCESSOR_TRAFFIC_MOVED,
};
use super::successor::{
    self, PolicyReadback, SuccessorKernel, SuccessorProgress, SuccessorRemovalProgress,
};
use super::LocalXfrmProfile;
use crate::{InstallSaRequest, LinuxXfrmBackend, RekeyPolicyRequest, XfrmBackend, XfrmError};

fn mismatch() -> XfrmError {
    XfrmError::StateMismatch {
        operation: "local_scope_successor_receipt",
    }
}

fn uncertain() -> XfrmError {
    XfrmError::StateIndeterminate {
        operation: "local_scope_effect",
    }
}

fn same_request(first: &crate::ScopedXfrmRequest, second: &crate::ScopedXfrmRequest) -> bool {
    first.sa == second.sa && first.policy == second.policy
}

enum SuccessorAction {
    Install,
    Remove,
}

enum SuccessorOutcome {
    Published,
    Undone,
    Removed,
}

impl Operations {
    pub(crate) async fn admit_successor(
        &mut self,
        backend: &LinuxXfrmBackend,
        profile: Option<&LocalXfrmProfile>,
        install: SuccessorInstall,
    ) {
        let SuccessorInstall {
            profile: supplied,
            effect,
            predecessor,
            request,
            guard,
            permit,
            reply,
        } = install;
        if !profile.is_some_and(|profile| Arc::ptr_eq(&profile.binding, &supplied.binding))
            || supplied.recheck().is_err()
            || guard.recheck().is_err()
            || !effect.matches_operation(&guard)
            || !backend.local_lifecycle().is_some_and(|lifecycle| {
                lifecycle
                    .local_scope()
                    .is_same_instance(guard.local_scope())
            })
        {
            let _ = reply.send(Err(mismatch()));
            return;
        }
        let Some(predecessor_index) = self
            .entries
            .iter()
            .position(|entry| entry.receipt.same_as(&predecessor))
        else {
            let _ = reply.send(Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_predecessor",
            }));
            return;
        };
        {
            let primary = &self.entries[predecessor_index];
            if primary.progress.undo || !primary.progress.published {
                let _ = reply.send(Err(XfrmError::StateMismatch {
                    operation: "local_scope_successor_predecessor",
                }));
                return;
            }
            if primary.successor.is_some() {
                let _ = reply.send(Err(XfrmError::AlreadyExists));
                return;
            }
        }
        // Exact retry of a lost admission/publication reply.
        if let Some(existing_index) = self
            .successors
            .iter()
            .position(|entry| entry.predecessor.same_as(&predecessor))
        {
            let existing = &self.successors[existing_index];
            let result = if same_request(&existing.request, &request)
                && existing.effect.key() == effect.key()
            {
                if existing.install_progress.published && !existing.removal_requested {
                    match Self::read_successor_entry(backend, existing).await {
                        Ok(true) => Ok(existing.receipt.clone()),
                        _ => Err(uncertain()),
                    }
                } else {
                    Err(uncertain())
                }
            } else {
                Err(XfrmError::AlreadyExists)
            };
            let _ = reply.send(result);
            return;
        }
        {
            let primary = &self.entries[predecessor_index];
            if let Err(error) = request.validate_successor_of(&primary.request) {
                let _ = reply.send(Err(error));
                return;
            }
        }
        let target = match request.policy.direction {
            crate::XfrmDirection::In => LocalEffectUse::XfrmInbound,
            crate::XfrmDirection::Out => LocalEffectUse::XfrmOutbound,
            crate::XfrmDirection::Forward => LocalEffectUse::XfrmForward,
        };
        let reservation = {
            let primary = &self.entries[predecessor_index];
            let Some(predecessor_reservation) = primary.reservation.as_ref() else {
                let _ = reply.send(Err(uncertain()));
                return;
            };
            match self
                .registry
                .reserve_successor(predecessor_reservation, Arc::clone(&request))
            {
                Ok(reservation) => reservation,
                Err(error) => {
                    let _ = reply.send(Err(error));
                    return;
                }
            }
        };
        // Consume the one-shot activation only after the last refusal gate, so
        // a refused reservation never burns committed authority.
        if effect.consume(target).is_err() {
            let _ = self.registry.retired(&reservation);
            let _ = reply.send(Err(mismatch()));
            return;
        }
        let receipt = ScopedXfrmReceipt::successor_receipt(&supplied, predecessor.clone());
        self.successors.push(SuccessorEntry {
            #[cfg(test)]
            fault: self.next_fault.take(),
            predecessor,
            request,
            receipt,
            effect,
            reservation: Some(reservation),
            guard: Some(guard),
            permit: Some(permit),
            observer: Some(reply),
            remover: None,
            install_progress: SuccessorProgress::default(),
            removal_progress: SuccessorRemovalProgress::default(),
            removal_requested: false,
            schedule: CleanupSchedule::default(),
        });
    }

    pub(crate) fn command_successor_remove(
        &mut self,
        receipt: ScopedXfrmReceipt,
        guard: LocalOperation,
        reply: oneshot::Sender<Result<(), XfrmError>>,
    ) {
        if receipt.role() != ReceiptRole::Successor || !receipt.epoch_matches(&guard) {
            let _ = reply.send(Err(mismatch()));
            return;
        }
        if receipt.is_retired() {
            let _ = reply.send(Ok(()));
            return;
        }
        let Some(index) = self
            .successors
            .iter()
            .position(|entry| entry.receipt.same_as(&receipt))
        else {
            let _ = reply.send(Err(mismatch()));
            return;
        };
        let entry = &mut self.successors[index];
        if entry.install_progress.published && !entry.predecessor.is_retired() {
            let _ = reply.send(Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_predecessor_live",
            }));
            return;
        }
        if let Some(previous) = entry.remover.replace(reply) {
            let _ = previous.send(Err(uncertain()));
        }
        entry.guard.get_or_insert(guard);
        if entry.install_progress.published {
            entry.removal_requested = true;
        } else {
            // Cancel before publication: undo the candidate through readback.
            entry.install_progress.undo = true;
        }
    }

    pub(crate) async fn read_successor(
        &self,
        backend: &LinuxXfrmBackend,
        receipt: &ScopedXfrmReceipt,
    ) -> Result<bool, XfrmError> {
        let Some(entry) = self
            .successors
            .iter()
            .find(|entry| entry.receipt.same_as(receipt))
        else {
            return if receipt.is_retired() {
                Ok(false)
            } else {
                Err(mismatch())
            };
        };
        if !entry.install_progress.published
            || entry.install_progress.undo
            || entry.removal_requested
        {
            return Err(uncertain());
        }
        Self::read_successor_entry(backend, entry).await
    }

    async fn read_successor_entry(
        backend: &LinuxXfrmBackend,
        entry: &SuccessorEntry,
    ) -> Result<bool, XfrmError> {
        let sa = backend.read_scoped_sa(&entry.request).await?;
        let policy = backend.read_scoped_policy(&entry.request).await;
        let policy_exact = matches!(policy, Ok(Readback::Exact));
        Ok(sa == Readback::Exact && policy_exact)
    }

    pub(crate) fn successor_status_for(
        &self,
        receipt: &ScopedXfrmReceipt,
    ) -> Result<ScopedXfrmSuccessorStatus, XfrmError> {
        match receipt.role() {
            ReceiptRole::Successor => Ok(receipt.status()),
            ReceiptRole::Install => {
                if let Some(entry) = self
                    .entries
                    .iter()
                    .find(|entry| entry.receipt.same_as(receipt))
                {
                    if let Some(link) = &entry.successor {
                        return Ok(link.receipt.status());
                    }
                }
                if receipt.has_successor_progress() {
                    Ok(receipt.status())
                } else {
                    Err(XfrmError::StateMismatch {
                        operation: "local_scope_successor_absent",
                    })
                }
            }
        }
    }

    /// Service at most one due successor or predecessor-retirement step.
    pub(crate) async fn service_successors(&mut self, backend: &LinuxXfrmBackend) -> bool {
        let now = tokio::time::Instant::now();
        if let Some(index) = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.retirement.is_some() && entry.schedule.next_attempt() <= now)
            .min_by_key(|(_, entry)| entry.schedule.next_attempt())
            .map(|(index, _)| index)
        {
            self.step_retirement_at(backend, index).await;
            return true;
        }
        let index = self
            .successors
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                (!entry.install_progress.published
                    || entry.install_progress.undo
                    || entry.removal_requested)
                    && entry.schedule.next_attempt() <= now
            })
            .min_by_key(|(_, entry)| entry.schedule.next_attempt())
            .map(|(index, _)| index);
        let Some(index) = index else {
            return false;
        };
        self.step_successor_at(backend, index).await;
        true
    }

    async fn step_successor_at(&mut self, backend: &LinuxXfrmBackend, index: usize) {
        let predecessor_request = {
            let Some(entry) = self.successors.get(index) else {
                return;
            };
            match self
                .entries
                .iter()
                .find(|primary| primary.receipt.same_as(&entry.predecessor))
            {
                Some(primary) => Arc::clone(&primary.request),
                None => {
                    if let Some(entry) = self.successors.get_mut(index) {
                        if let Some(remover) = entry.remover.take() {
                            let _ = remover.send(Err(XfrmError::StateMismatch {
                                operation: "local_scope_successor_predecessor",
                            }));
                        }
                        entry.install_progress.undo = true;
                    }
                    return;
                }
            }
        };
        let predecessor_retired = {
            let Some(entry) = self.successors.get(index) else {
                return;
            };
            entry.predecessor.is_retired()
        };
        let outcome = {
            let Some(entry) = self.successors.get_mut(index) else {
                return;
            };
            let Some(attempt) = entry.schedule.begin() else {
                return;
            };
            if entry
                .observer
                .as_ref()
                .is_some_and(oneshot::Sender::is_closed)
                && !entry.install_progress.published
            {
                entry.install_progress.undo = true;
            }
            if !entry.install_progress.published && entry.effect.recheck_local_execution().is_err()
            {
                entry.install_progress.undo = true;
            }
            if entry.guard.is_none() {
                match entry.receipt.profile().try_begin_operation() {
                    Ok(Some(guard)) => entry.guard = Some(guard),
                    Ok(None) => {
                        entry.schedule.failed(rand::random());
                        return;
                    }
                    Err(_) => {
                        entry.schedule.failed(rand::random());
                        return;
                    }
                }
            }
            let Some(guard) = entry.guard.as_ref() else {
                return;
            };
            let action = if entry.install_progress.published {
                if !entry.removal_requested {
                    return;
                }
                SuccessorAction::Remove
            } else {
                SuccessorAction::Install
            };
            let mut kernel = NativeSuccessorKernel {
                #[cfg(test)]
                fault: &mut entry.fault,
                backend,
                guard,
                effect: &entry.effect,
                predecessor_request,
                request: Arc::clone(&entry.request),
                attempt,
            };
            let install_progress = &mut entry.install_progress;
            let removal_progress = &mut entry.removal_progress;
            let observer = &entry.observer;
            let work = async {
                match action {
                    SuccessorAction::Install => {
                        if install_progress.undo {
                            successor::undo(&mut kernel, install_progress).await
                        } else {
                            successor::install(&mut kernel, install_progress).await?;
                            successor::publish(&mut kernel, install_progress, || {
                                observer.as_ref().is_none_or(oneshot::Sender::is_closed)
                            })
                            .await
                        }
                    }
                    SuccessorAction::Remove => {
                        successor::remove_successor(
                            &mut kernel,
                            removal_progress,
                            predecessor_retired,
                        )
                        .await
                    }
                }
            };
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                std::panic::AssertUnwindSafe(work).catch_unwind(),
            )
            .await;
            if !matches!(result, Ok(Ok(Ok(())))) {
                if !entry.install_progress.published {
                    entry.install_progress.undo = true;
                    entry.schedule.failed(rand::random());
                    return;
                }
                if let Ok(Ok(Err(error @ XfrmError::StateMismatch { .. }))) = result {
                    entry.removal_requested = false;
                    if let Some(remover) = entry.remover.take() {
                        let _ = remover.send(Err(error));
                    }
                    return;
                }
                if let Some(observer) = entry.observer.take() {
                    let _ = observer.send(Err(uncertain()));
                }
                entry.removal_requested = false;
                entry.schedule.failed(rand::random());
                return;
            }
            match action {
                SuccessorAction::Remove => SuccessorOutcome::Removed,
                SuccessorAction::Install if entry.install_progress.published => {
                    SuccessorOutcome::Published
                }
                SuccessorAction::Install => SuccessorOutcome::Undone,
            }
        };
        match outcome {
            SuccessorOutcome::Published => {
                let receipt = {
                    let Some(entry) = self.successors.get_mut(index) else {
                        return;
                    };
                    entry.receipt.mark_successor_flags(
                        SUCCESSOR_SA_INSTALLED | SUCCESSOR_TRAFFIC_MOVED | SUCCESSOR_PUBLISHED,
                    );
                    let link = SuccessorLink {
                        request: Arc::clone(&entry.request),
                        receipt: entry.receipt.clone(),
                    };
                    let receipt = entry.receipt.clone();
                    if let Some(primary) = self
                        .entries
                        .iter_mut()
                        .find(|primary| primary.receipt.same_as(&entry.predecessor))
                    {
                        primary.receipt.mark_successor_flags(
                            SUCCESSOR_SA_INSTALLED | SUCCESSOR_TRAFFIC_MOVED | SUCCESSOR_PUBLISHED,
                        );
                        primary.successor = Some(link);
                    }
                    #[cfg(test)]
                    if matches!(entry.fault, Some(TestFault::DropSuccessorReply)) {
                        entry.fault = None;
                        entry.observer = None;
                    }
                    let _ = entry
                        .observer
                        .take()
                        .map(|observer| observer.send(Ok(receipt.clone())));
                    entry.guard = None;
                    entry.permit = None;
                    receipt
                };
                let _ = receipt;
            }
            SuccessorOutcome::Undone | SuccessorOutcome::Removed => {
                let mut removed = self.successors.remove(index);
                let _ = removed.reservation.as_ref().map(|reservation| {
                    let _ = self.registry.check_successor_release(reservation);
                    let _ = self.registry.retired(reservation);
                });
                removed.receipt.binding_retire();
                let _ = removed
                    .observer
                    .take()
                    .map(|observer| observer.send(Err(uncertain())));
                let _ = removed.remover.take().map(|remover| remover.send(Ok(())));
            }
        }
    }

    async fn step_retirement_at(&mut self, backend: &LinuxXfrmBackend, index: usize) {
        let successor_request = {
            let Some(entry) = self.entries.get(index) else {
                return;
            };
            let Some(link) = &entry.successor else {
                return;
            };
            Arc::clone(&link.request)
        };
        let outcome = {
            let Some(entry) = self.entries.get_mut(index) else {
                return;
            };
            let Some(attempt) = entry.schedule.begin() else {
                return;
            };
            let Some(retirement) = entry.retirement.as_mut() else {
                return;
            };
            if entry.guard.is_none() {
                match entry.receipt.profile().try_begin_operation() {
                    Ok(Some(guard)) => entry.guard = Some(guard),
                    Ok(None) => {
                        entry.schedule.failed(rand::random());
                        return;
                    }
                    Err(_) => {
                        entry.schedule.failed(rand::random());
                        return;
                    }
                }
            }
            let Some(guard) = entry.guard.as_ref() else {
                return;
            };
            let mut kernel = NativeSuccessorKernel {
                #[cfg(test)]
                fault: &mut entry.fault,
                backend,
                guard,
                effect: &entry.effect,
                predecessor_request: Arc::clone(&entry.request),
                request: successor_request,
                attempt,
            };
            let work = successor::retire_predecessor(&mut kernel, retirement);
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                std::panic::AssertUnwindSafe(work).catch_unwind(),
            )
            .await;
            if !matches!(result, Ok(Ok(Ok(())))) {
                // A definitive refusal releases the request; an unresolved
                // removal stays supervised for readback.
                let definitive = matches!(result, Ok(Ok(Err(XfrmError::StateMismatch { .. }))));
                if definitive {
                    entry.retirement = None;
                    if let Some(remover) = entry.remover.take() {
                        let _ = remover.send(Err(XfrmError::StateMismatch {
                            operation: "local_scope_successor_not_live",
                        }));
                    }
                } else {
                    entry.schedule.failed(rand::random());
                }
                return;
            }
            true
        };
        if !outcome {
            return;
        }
        let mut removed = self.entries.remove(index);
        let _ = removed.reservation.as_ref().map(|reservation| {
            let _ = self.registry.retire_predecessor(reservation);
        });
        removed.receipt.mark_successor_flags(PREDECESSOR_RETIRED);
        removed.receipt.binding_retire();
        if let Some(entry) = self
            .successors
            .iter()
            .find(|entry| entry.predecessor.same_as(&removed.receipt))
        {
            entry.receipt.mark_successor_flags(PREDECESSOR_RETIRED);
        }
        let _ = removed.remover.take().map(|remover| remover.send(Ok(())));
    }
}

struct NativeSuccessorKernel<'a> {
    #[cfg(test)]
    fault: &'a mut Option<TestFault>,
    backend: &'a LinuxXfrmBackend,
    guard: &'a LocalOperation,
    effect: &'a CommittedScopeEffect,
    predecessor_request: Arc<crate::ScopedXfrmRequest>,
    request: Arc<crate::ScopedXfrmRequest>,
    attempt: CleanupAttempt,
}

impl NativeSuccessorKernel<'_> {
    async fn read_policy(
        &mut self,
        request: &crate::ScopedXfrmRequest,
    ) -> Result<PolicyReadback, XfrmError> {
        self.local()?;
        match self.backend.read_scoped_policy(request).await {
            Ok(Readback::Exact) => Ok(PolicyReadback::Exact),
            Ok(Readback::Absent) => Ok(PolicyReadback::Absent),
            Err(XfrmError::StateMismatch { .. }) => Ok(PolicyReadback::Other),
            Err(error) => Err(error),
        }
    }
}

#[async_trait::async_trait]
impl SuccessorKernel for NativeSuccessorKernel<'_> {
    fn outbound(&self) -> bool {
        self.request.policy.direction == crate::XfrmDirection::Out
    }
    fn local(&self) -> Result<(), XfrmError> {
        #[cfg(test)]
        if let Some(TestFault::HoldSuccessorSa(hold) | TestFault::HoldSuccessorSelection(hold)) =
            self.fault
        {
            if hold.reached.load(Ordering::Acquire) && !hold.resume.load(Ordering::Acquire) {
                return Err(uncertain());
            }
        }
        if !self.attempt.has_budget() {
            return Err(uncertain());
        }
        self.guard.recheck().map_err(|_| mismatch())?;
        self.backend.verify_namespace_actor()
    }
    fn publication(&self) -> Result<(), XfrmError> {
        self.local()?;
        self.effect
            .recheck_local_execution()
            .map_err(|_| uncertain())
    }
    async fn current(&self) -> Result<(), XfrmError> {
        self.local()?;
        if !self.effect.matches_operation(self.guard) {
            return Err(mismatch());
        }
        self.backend.preflight_scoped_sa(&self.request)?;
        self.effect.recheck().await.map_err(|_| uncertain())
    }
    async fn predecessor_sa(&mut self) -> Result<Readback, XfrmError> {
        self.local()?;
        self.backend.read_scoped_sa(&self.predecessor_request).await
    }
    async fn predecessor_policy(&mut self) -> Result<PolicyReadback, XfrmError> {
        let request = Arc::clone(&self.predecessor_request);
        self.read_policy(&request).await
    }
    async fn successor_sa(&mut self) -> Result<Readback, XfrmError> {
        self.local()?;
        self.backend.read_scoped_sa(&self.request).await
    }
    async fn successor_policy(&mut self) -> Result<PolicyReadback, XfrmError> {
        let request = Arc::clone(&self.request);
        self.read_policy(&request).await
    }
    async fn create_successor_sa(&mut self) -> Result<(), XfrmError> {
        self.local()?;
        let result = self
            .backend
            .install_sa(InstallSaRequest {
                parameters: self.request.sa.clone(),
            })
            .await;
        #[cfg(test)]
        match self.fault {
            Some(TestFault::PanicAfterSuccessorSa) => {
                *self.fault = None;
                panic!("injected failure after successor SA installation");
            }
            Some(TestFault::HoldSuccessorSa(hold)) => {
                hold.reached.store(true, Ordering::Release);
                hold.entered.notify_one();
            }
            _ => {}
        }
        result
    }
    async fn move_policy_to_successor(&mut self) -> Result<(), XfrmError> {
        self.local()?;
        let result = self
            .backend
            .rekey_policy(RekeyPolicyRequest {
                parameters: self.request.policy.clone(),
            })
            .await;
        #[cfg(test)]
        match self.fault {
            Some(TestFault::PanicAfterSuccessorSelection) => {
                *self.fault = None;
                panic!("injected failure after successor policy selection");
            }
            Some(TestFault::HoldSuccessorSelection(hold)) => {
                hold.reached.store(true, Ordering::Release);
                hold.entered.notify_one();
            }
            _ => {}
        }
        result
    }
    async fn restore_policy_to_predecessor(&mut self) -> Result<(), XfrmError> {
        self.local()?;
        self.backend
            .rekey_policy(RekeyPolicyRequest {
                parameters: self.predecessor_request.policy.clone(),
            })
            .await
    }
    async fn remove_successor_sa(&mut self) -> Result<(), XfrmError> {
        self.local()?;
        let local = || self.local();
        self.backend.remove_scoped_sa(&self.request, local).await
    }
    async fn remove_successor_policy(&mut self) -> Result<(), XfrmError> {
        self.local()?;
        let local = || self.local();
        self.backend
            .remove_scoped_policy(&self.request, local)
            .await
    }
    async fn remove_predecessor_sa(&mut self) -> Result<(), XfrmError> {
        self.local()?;
        let local = || self.local();
        self.backend
            .remove_scoped_sa(&self.predecessor_request, local)
            .await
    }
}
