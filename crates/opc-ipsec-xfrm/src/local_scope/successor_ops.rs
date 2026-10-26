//! Actor-owned successor admission, recovery, fresh status and group retirement.

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

use super::effect::{self, Readback};
use super::operations::{
    Entry, GroupRetirement, Operations, RetirementPlan, ScopedXfrmReceipt,
    ScopedXfrmSuccessorStatus, SuccessorEntry, SuccessorInstall, SuccessorOrigin,
};
use super::successor::{self, PolicyReadback, SuccessorKernel, SuccessorProgress};
use super::{LocalXfrmProfile, ScopedXfrmRequest};
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
fn pending() -> XfrmError {
    XfrmError::StateMismatch {
        operation: "local_scope_successor_pending",
    }
}
fn not_live() -> XfrmError {
    XfrmError::StateMismatch {
        operation: "local_scope_successor_not_live",
    }
}
fn same_request(first: &ScopedXfrmRequest, second: &ScopedXfrmRequest) -> bool {
    first.sa == second.sa && first.policy == second.policy
}
async fn read_policy(
    backend: &LinuxXfrmBackend,
    request: &ScopedXfrmRequest,
) -> Result<PolicyReadback, XfrmError> {
    match backend.read_scoped_policy(request).await {
        Ok(Readback::Exact) => Ok(PolicyReadback::Exact),
        Ok(Readback::Absent) => Ok(PolicyReadback::Absent),
        Err(XfrmError::StateMismatch { .. }) => Ok(PolicyReadback::Other),
        Err(error) => Err(error),
    }
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
            || !predecessor.epoch_matches(&guard)
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
        // Reply loss is resolved before predecessor liveness, new admission or
        // one-shot consumption. The predecessor may already have been retired.
        if let Some(entry) = self.entries.iter().find(|entry| {
            entry
                .origin
                .as_ref()
                .is_some_and(|origin| origin.predecessor.same_as(&predecessor))
        }) {
            let result =
                if entry.effect.key() != effect.key() || !same_request(&entry.request, &request) {
                    Err(XfrmError::AlreadyExists)
                } else if entry.retirement.is_some() || entry.progress.undo {
                    Err(uncertain())
                } else {
                    match Self::read(backend, entry).await {
                        Ok(true) => Ok(entry.receipt.clone()),
                        Ok(false) => Err(uncertain()),
                        Err(error) => Err(error),
                    }
                };
            let _ = reply.send(result);
            return;
        }
        if let Some(entry) = self
            .successors
            .iter_mut()
            .find(|entry| entry.predecessor.same_as(&predecessor))
        {
            if entry.effect.key() != effect.key() || !same_request(&entry.request, &request) {
                let _ = reply.send(Err(XfrmError::AlreadyExists));
            } else if entry.install_progress.undo {
                let _ = reply.send(Err(uncertain()));
            } else if let Some(previous) = entry.observer.replace(reply) {
                let _ = previous.send(Err(uncertain()));
            }
            return;
        }
        if self
            .entries
            .iter()
            .map(|entry| entry.effect.key())
            .chain(self.successors.iter().map(|entry| entry.effect.key()))
            .any(|key| key.same_request_id(effect.key()) && key.request() != effect.key().request())
        {
            let _ = reply.send(Err(mismatch()));
            return;
        }
        let Some(primary) = self
            .entries
            .iter()
            .find(|entry| entry.receipt.same_as(&predecessor))
        else {
            let _ = reply.send(Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_predecessor",
            }));
            return;
        };
        if !primary.progress.published || primary.progress.undo || primary.retirement.is_some() {
            let _ = reply.send(Err(pending()));
            return;
        }
        if !Arc::ptr_eq(&primary.request, &primary.protection) {
            let _ = reply.send(Err(XfrmError::AlreadyExists));
            return;
        }
        if let Err(error) = request.validate_successor_of(&primary.request) {
            let _ = reply.send(Err(error));
            return;
        }
        let Some(previous_reservation) = primary.reservation.as_ref() else {
            let _ = reply.send(Err(uncertain()));
            return;
        };
        if self
            .successors
            .iter()
            .any(|entry| entry.reservation.shares_policy(previous_reservation))
            || self.entries.iter().any(|entry| {
                entry.retirement.is_some()
                    && entry
                        .reservation
                        .as_ref()
                        .is_some_and(|reservation| reservation.shares_policy(previous_reservation))
            })
        {
            let _ = reply.send(Err(pending()));
            return;
        }
        let predecessor_request = primary.request.clone();
        let reservation = match self
            .registry
            .reserve_successor(previous_reservation, request.clone())
        {
            Ok(reservation) => reservation,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        let target = match request.policy.direction {
            crate::XfrmDirection::In => LocalEffectUse::XfrmInbound,
            crate::XfrmDirection::Out => LocalEffectUse::XfrmOutbound,
            crate::XfrmDirection::Forward => LocalEffectUse::XfrmForward,
        };
        if effect.consume(target).is_err() {
            let _ = self.registry.retired(&reservation);
            let _ = reply.send(Err(mismatch()));
            return;
        }
        self.successors.push(SuccessorEntry {
            #[cfg(test)]
            fault: self.next_fault.take(),
            predecessor,
            predecessor_request,
            request,
            receipt: ScopedXfrmReceipt::new(supplied),
            effect,
            reservation,
            guard,
            permit,
            observer: Some(reply),
            install_progress: SuccessorProgress::default(),
            schedule: CleanupSchedule::default(),
        });
    }

    pub(crate) fn command_member_remove(
        &mut self,
        receipt: ScopedXfrmReceipt,
        guard: LocalOperation,
        reply: oneshot::Sender<Result<(), XfrmError>>,
    ) {
        if !receipt.epoch_matches(&guard) {
            let _ = reply.send(Err(mismatch()));
            return;
        }
        if receipt.is_retired() {
            let _ = reply.send(Ok(()));
            return;
        }
        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.receipt.same_as(&receipt))
        else {
            let _ = reply.send(Err(mismatch()));
            return;
        };
        let entry = &self.entries[index];
        if !entry.progress.published || entry.progress.undo {
            let _ = reply.send(Err(uncertain()));
            return;
        }
        let Some(reservation) = entry.reservation.as_ref() else {
            let _ = reply.send(Err(uncertain()));
            return;
        };
        if self
            .successors
            .iter()
            .any(|candidate| candidate.reservation.shares_policy(reservation))
            || self.entries.iter().enumerate().any(|(other_index, other)| {
                other_index != index
                    && other.retirement.is_some()
                    && other
                        .reservation
                        .as_ref()
                        .is_some_and(|other| other.shares_policy(reservation))
            })
        {
            let _ = reply.send(Err(pending()));
            return;
        }
        let entry = &mut self.entries[index];
        if let Some(previous) = entry.remover.replace(reply) {
            let _ = previous.send(Err(uncertain()));
        }
        entry.guard.get_or_insert(guard);
        if entry.retirement.is_none() {
            entry.retirement = Some(GroupRetirement::default());
            entry.schedule = CleanupSchedule::default();
        }
    }

    pub(crate) async fn successor_status_for(
        &self,
        backend: &LinuxXfrmBackend,
        receipt: &ScopedXfrmReceipt,
        guard: &LocalOperation,
    ) -> Result<ScopedXfrmSuccessorStatus, XfrmError> {
        if !receipt.epoch_matches(guard) {
            return Err(mismatch());
        }
        receipt.profile().recheck()?;
        let pending = self
            .successors
            .iter()
            .find(|entry| entry.predecessor.same_as(receipt));
        let published = self
            .entries
            .iter()
            .find(|entry| {
                entry
                    .origin
                    .as_ref()
                    .is_some_and(|origin| origin.predecessor.same_as(receipt))
            })
            .or_else(|| {
                self.entries
                    .iter()
                    .find(|entry| entry.receipt.same_as(receipt) && entry.origin.is_some())
            });
        let (predecessor, successor, published) = if let Some(entry) = pending {
            (
                &entry.predecessor_request,
                &entry.request,
                entry.install_progress.published,
            )
        } else if let Some(entry) = published {
            let Some(origin) = entry.origin.as_ref() else {
                return Err(uncertain());
            };
            (
                &origin.predecessor_request,
                &entry.request,
                entry.progress.published,
            )
        } else {
            return Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_absent",
            });
        };
        let successor_sa_installed = backend.read_scoped_sa(successor).await? == Readback::Exact;
        let traffic_moved = read_policy(backend, successor).await? == PolicyReadback::Exact
            && successor_sa_installed;
        let predecessor_retired = backend.read_scoped_sa(predecessor).await? == Readback::Absent;
        if !receipt.epoch_matches(guard) {
            return Err(mismatch());
        }
        Ok(ScopedXfrmSuccessorStatus {
            successor_sa_installed,
            traffic_moved,
            published,
            predecessor_retired,
        })
    }

    /// Service one due transition, while unrelated groups keep making progress.
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
        if let Some(index) = self
            .successors
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.schedule.next_attempt() <= now)
            .min_by_key(|(_, entry)| entry.schedule.next_attempt())
            .map(|(index, _)| index)
        {
            self.step_successor_at(backend, index).await;
            return true;
        }
        false
    }

    async fn step_successor_at(&mut self, backend: &LinuxXfrmBackend, index: usize) {
        let entry = &mut self.successors[index];
        let Some(attempt) = entry.schedule.begin() else {
            return;
        };
        if !entry.install_progress.published && entry.effect.recheck_local_execution().is_err() {
            entry.install_progress.undo = true;
        }
        let mut kernel = NativeSuccessorKernel {
            #[cfg(test)]
            fault: &mut entry.fault,
            backend,
            guard: &entry.guard,
            effect: &entry.effect,
            predecessor_request: entry.predecessor_request.clone(),
            request: entry.request.clone(),
            attempt,
        };
        let progress = &mut entry.install_progress;
        let work = async {
            if progress.undo {
                successor::undo(&mut kernel, progress).await
            } else {
                successor::install(&mut kernel, progress).await?;
                successor::publish(&mut kernel, progress, || false).await
            }
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            std::panic::AssertUnwindSafe(work).catch_unwind(),
        )
        .await;
        if !matches!(result, Ok(Ok(Ok(())))) && !entry.install_progress.published {
            // Uncertain reads, timeout and panic retain forward progress. Only
            // a definitive refusal or a local fence authorizes reverse undo.
            if matches!(
                result,
                Ok(Ok(Err(XfrmError::StateMismatch { .. }
                    | XfrmError::InvalidConfig { .. }
                    | XfrmError::AlreadyExists)))
            ) {
                entry.install_progress.undo = true;
            }
            if entry.install_progress.undo || !matches!(result, Ok(Ok(Err(_)))) {
                if let Some(observer) = entry.observer.take() {
                    let _ = observer.send(Err(uncertain()));
                }
            }
            entry.schedule.failed(rand::random());
            return;
        }
        if entry.install_progress.retired {
            if self.registry.retired(&entry.reservation).is_err() {
                entry.schedule.failed(rand::random());
                return;
            }
            let mut entry = self.successors.remove(index);
            entry.receipt.binding_retire();
            if let Some(observer) = entry.observer.take() {
                let _ = observer.send(Err(uncertain()));
            }
        } else if entry.install_progress.published {
            let mut entry = self.successors.remove(index);
            for member in &mut self.entries {
                if member
                    .reservation
                    .as_ref()
                    .is_some_and(|reservation| reservation.shares_policy(&entry.reservation))
                {
                    member.protection = entry.request.clone();
                }
            }
            #[cfg(test)]
            if matches!(entry.fault, Some(TestFault::DropSuccessorReply)) {
                entry.fault = None;
                entry.observer = None;
            }
            let receipt = entry.receipt.clone();
            self.entries.push(Entry {
                #[cfg(test)]
                fault: entry.fault,
                effect: entry.effect,
                request: entry.request.clone(),
                protection: entry.request,
                receipt: entry.receipt,
                reservation: Some(entry.reservation),
                guard: None,
                permit: None,
                observer: None,
                remover: None,
                progress: effect::Progress {
                    policy_started: true,
                    sa_started: true,
                    installed: true,
                    published: true,
                    undo: false,
                    retired: false,
                },
                origin: Some(SuccessorOrigin {
                    predecessor: entry.predecessor,
                    predecessor_request: entry.predecessor_request,
                }),
                retirement: None,
                schedule: CleanupSchedule::default(),
            });
            if let Some(observer) = entry.observer.take() {
                let _ = observer.send(Ok(receipt));
            }
            drop(entry.guard);
            drop(entry.permit);
        }
    }

    async fn retirement_plan(
        &self,
        backend: &LinuxXfrmBackend,
        index: usize,
        attempt: CleanupAttempt,
    ) -> Result<RetirementPlan, XfrmError> {
        let entry = &self.entries[index];
        let reservation = entry.reservation.as_ref().ok_or_else(uncertain)?;
        let others = self
            .entries
            .iter()
            .enumerate()
            .rev()
            .filter(|(other_index, other)| {
                *other_index != index
                    && other
                        .reservation
                        .as_ref()
                        .is_some_and(|other| other.shares_policy(reservation))
            })
            .map(|(_, other)| other.request.clone())
            .collect::<Vec<_>>();
        if others.is_empty() {
            return Ok(RetirementPlan::Final);
        }
        if !Arc::ptr_eq(&entry.request, &entry.protection) {
            return Ok(RetirementPlan::Keep(entry.protection.clone()));
        }
        for request in &others {
            if !attempt.has_budget() {
                return Err(uncertain());
            }
            if backend.read_scoped_sa(request).await? == Readback::Exact {
                return Ok(RetirementPlan::Restore(request.clone()));
            }
        }
        if !attempt.has_budget() {
            return Err(uncertain());
        }
        if backend.read_scoped_sa(&entry.request).await? != Readback::Absent {
            return Err(not_live());
        }
        // All members expired. Restore any retained member's protection so the
        // final receipt can remove that same policy after proving SA absence.
        others
            .first()
            .cloned()
            .map(RetirementPlan::Restore)
            .ok_or_else(uncertain)
    }

    async fn step_retirement_at(&mut self, backend: &LinuxXfrmBackend, index: usize) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let Some(attempt) = self.entries[index].schedule.begin() else {
            return;
        };
        if self.entries[index]
            .retirement
            .as_ref()
            .is_some_and(|retirement| retirement.plan.is_none())
        {
            let planning =
                std::panic::AssertUnwindSafe(self.retirement_plan(backend, index, attempt))
                    .catch_unwind();
            match tokio::time::timeout_at(deadline, planning).await {
                Ok(Ok(Ok(plan))) => {
                    if let Some(retirement) = &mut self.entries[index].retirement {
                        retirement.plan = Some(plan);
                    }
                }
                Ok(Ok(Err(error @ XfrmError::StateMismatch { .. }))) => {
                    let entry = &mut self.entries[index];
                    entry.retirement = None;
                    entry.guard = None;
                    if let Some(remover) = entry.remover.take() {
                        let _ = remover.send(Err(error));
                    }
                    return;
                }
                _ => {
                    self.entries[index].schedule.failed(rand::random());
                    return;
                }
            }
        }
        let entry = &mut self.entries[index];
        let Some(guard) = entry.guard.as_ref() else {
            return;
        };
        let Some(retirement) = entry.retirement.as_mut() else {
            return;
        };
        let Some(plan) = retirement.plan.clone() else {
            return;
        };
        let (predecessor_request, request) = match &plan {
            RetirementPlan::Keep(selected) => (entry.request.clone(), selected.clone()),
            RetirementPlan::Restore(replacement) => (replacement.clone(), entry.request.clone()),
            RetirementPlan::Final => (entry.request.clone(), entry.request.clone()),
        };
        let mut kernel = NativeSuccessorKernel {
            #[cfg(test)]
            fault: &mut entry.fault,
            backend,
            guard,
            effect: &entry.effect,
            predecessor_request,
            request,
            attempt,
        };
        let work = async {
            match &plan {
                RetirementPlan::Keep(_) => {
                    successor::retire_predecessor(&mut kernel, &mut retirement.predecessor).await
                }
                RetirementPlan::Restore(_) => {
                    successor::remove_successor(&mut kernel, &mut retirement.removal, false).await
                }
                RetirementPlan::Final => {
                    successor::remove_successor(&mut kernel, &mut retirement.removal, true).await
                }
            }
        };
        let result =
            tokio::time::timeout_at(deadline, std::panic::AssertUnwindSafe(work).catch_unwind())
                .await;
        let selection = match &plan {
            RetirementPlan::Restore(replacement) if retirement.removal.restored => {
                Some(replacement.clone())
            }
            _ => None,
        };
        if let Some(selection) = selection {
            let reservation = entry.reservation.clone();
            for member in &mut self.entries {
                if member
                    .reservation
                    .as_ref()
                    .zip(reservation.as_ref())
                    .is_some_and(|(a, b)| a.shares_policy(b))
                {
                    member.protection = selection.clone();
                }
            }
        }
        let entry = &mut self.entries[index];
        if !matches!(result, Ok(Ok(Ok(())))) {
            if let Ok(Ok(Err(error @ XfrmError::StateMismatch { .. }))) = result {
                entry.retirement = None;
                entry.guard = None;
                if let Some(remover) = entry.remover.take() {
                    let _ = remover.send(Err(error));
                }
            } else {
                entry.schedule.failed(rand::random());
            }
            return;
        }
        let Some(reservation) = entry.reservation.as_ref() else {
            entry.schedule.failed(rand::random());
            return;
        };
        let retired = if matches!(plan, RetirementPlan::Keep(_)) {
            self.registry.retire_predecessor(reservation)
        } else {
            self.registry.retired(reservation)
        };
        if retired.is_err() {
            entry.schedule.failed(rand::random());
            return;
        }
        let mut removed = self.entries.remove(index);
        removed.receipt.binding_retire();
        if let Some(remover) = removed.remover.take() {
            let _ = remover.send(Ok(()));
        }
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
            self.fault.as_ref()
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
        self.effect.recheck().await.map_err(|error| match error {
            opc_local_kernel_lifecycle::LocalEffectError::Closed
            | opc_local_kernel_lifecycle::LocalEffectError::Stale
            | opc_local_kernel_lifecycle::LocalEffectError::WrongRequest => mismatch(),
            opc_local_kernel_lifecycle::LocalEffectError::TransportRevisionMismatch => {
                XfrmError::StateIndeterminate {
                    operation: "scope_transport_revision_mismatch",
                }
            }
            _ => uncertain(),
        })
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
