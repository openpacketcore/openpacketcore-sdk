//! One namespace actor owns transient intent, publication and exact undo.

use super::{effect, registry::Registry, LocalXfrmProfile, ScopedXfrmRequest};
use crate::{InstallPolicyRequest, InstallSaRequest, LinuxXfrmBackend, XfrmBackend, XfrmError};
use futures_util::FutureExt;
use opc_local_kernel_lifecycle::{
    CleanupAttempt, CleanupProgress, CleanupSchedule, CommittedScopeEffect, LocalEffectUse,
    LocalOperation,
};
use std::{
    panic::AssertUnwindSafe,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{oneshot, OwnedSemaphorePermit};

/// A process-local receipt for one actor-published SA and protective policy.
/// It cannot be deserialized, transplanted to another actor, or reused after
/// reset. Dropping this receipt never removes published forwarding.
#[derive(Clone)]
pub struct ScopedXfrmReceipt {
    binding: Arc<ReceiptBinding>,
}
struct ReceiptBinding {
    profile: LocalXfrmProfile,
    retired: AtomicBool,
}
impl std::fmt::Debug for ScopedXfrmReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScopedXfrmReceipt")
    }
}
impl ScopedXfrmReceipt {
    pub(crate) async fn begin(&self) -> Result<LocalOperation, XfrmError> {
        self.binding.profile.begin().await
    }
}

pub(crate) struct Install {
    pub(crate) profile: LocalXfrmProfile,
    pub(crate) effect: CommittedScopeEffect,
    pub(crate) request: Arc<ScopedXfrmRequest>,
    pub(crate) guard: LocalOperation,
    pub(crate) permit: OwnedSemaphorePermit,
    pub(crate) reply: oneshot::Sender<Result<ScopedXfrmReceipt, XfrmError>>,
}
pub(crate) enum Command {
    #[cfg(test)]
    Retained(oneshot::Sender<Result<usize, XfrmError>>),
    #[cfg(test)]
    Fault(TestFault, oneshot::Sender<Result<(), XfrmError>>),
    Install(Box<Install>),
    Remove {
        receipt: ScopedXfrmReceipt,
        guard: LocalOperation,
        reply: oneshot::Sender<Result<(), XfrmError>>,
    },
    Read {
        receipt: ScopedXfrmReceipt,
        guard: LocalOperation,
        reply: oneshot::Sender<Result<bool, XfrmError>>,
    },
    Progress(oneshot::Sender<Result<Vec<CleanupProgress>, XfrmError>>),
}
impl Command {
    pub(crate) fn send_error(self, error: XfrmError) {
        match self {
            #[cfg(test)]
            Self::Retained(reply) => {
                let _ = reply.send(Err(error));
            }
            #[cfg(test)]
            Self::Fault(_, reply) => {
                let _ = reply.send(Err(error));
            }
            Self::Install(install) => {
                let _ = install.reply.send(Err(error));
            }
            Self::Remove { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Read { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Progress(reply) => {
                let _ = reply.send(Err(error));
            }
        }
    }
}
struct Entry {
    #[cfg(test)]
    fault: Option<TestFault>,
    effect: CommittedScopeEffect,
    request: Arc<ScopedXfrmRequest>,
    receipt: ScopedXfrmReceipt,
    reservation: Option<super::registry::Reservation>,
    guard: Option<LocalOperation>,
    permit: Option<OwnedSemaphorePermit>,
    observer: Option<oneshot::Sender<Result<ScopedXfrmReceipt, XfrmError>>>,
    remover: Option<oneshot::Sender<Result<(), XfrmError>>>,
    progress: effect::Progress,
    schedule: CleanupSchedule,
}
#[derive(Default)]
pub(crate) struct Operations {
    #[cfg(test)]
    next_fault: Option<TestFault>,
    registry: Registry,
    entries: Vec<Entry>,
}
fn mismatch() -> XfrmError {
    XfrmError::StateMismatch {
        operation: "local_scope_receipt",
    }
}
fn uncertain() -> XfrmError {
    XfrmError::StateIndeterminate {
        operation: "local_scope_effect",
    }
}
fn same_receipt(first: &ScopedXfrmReceipt, second: &ScopedXfrmReceipt) -> bool {
    Arc::ptr_eq(&first.binding, &second.binding)
}
impl Operations {
    pub(crate) fn clear_after_reset(&mut self) {
        // The lifecycle's exclusive barrier has already drained every held
        // operation, and namespace reset freshly proved all SPD/SAD absent.
        *self = Self::default();
    }
    pub(crate) fn next_attempt(&self) -> Option<tokio::time::Instant> {
        self.entries
            .iter()
            .filter(|entry| !entry.progress.published || entry.progress.undo)
            .map(|entry| entry.schedule.next_attempt())
            .min()
    }
    pub(crate) async fn command(
        &mut self,
        backend: &LinuxXfrmBackend,
        profile: Option<&LocalXfrmProfile>,
        profile_progress: Option<CleanupProgress>,
        command: Command,
    ) {
        match command {
            #[cfg(test)]
            Command::Retained(reply) => {
                let _ = reply.send(Ok(self.entries.len()));
            }
            #[cfg(test)]
            Command::Fault(fault, reply) => {
                self.next_fault = Some(fault);
                let _ = reply.send(Ok(()));
            }
            Command::Install(install) => self.admit(backend, profile, *install).await,
            Command::Remove {
                receipt,
                guard,
                reply,
            } => {
                if guard.recheck().is_err()
                    || !guard
                        .epoch()
                        .is_same(&receipt.binding.profile.binding.epoch)
                {
                    let _ = reply.send(Err(mismatch()));
                    return;
                }
                if receipt.binding.retired.load(Ordering::Acquire) {
                    let _ = reply.send(Ok(()));
                } else if let Some(entry) = self
                    .entries
                    .iter_mut()
                    .find(|entry| same_receipt(&entry.receipt, &receipt))
                {
                    if let Some(previous) = entry.remover.replace(reply) {
                        let _ = previous.send(Err(uncertain()));
                    }
                    entry.guard.get_or_insert(guard);
                    entry.progress.undo = true;
                } else {
                    let _ = reply.send(Err(mismatch()));
                }
            }
            Command::Read {
                receipt,
                guard,
                reply,
            } => {
                let result = if guard.recheck().is_err()
                    || !guard
                        .epoch()
                        .is_same(&receipt.binding.profile.binding.epoch)
                {
                    Err(mismatch())
                } else if let Some(entry) = self
                    .entries
                    .iter()
                    .find(|entry| same_receipt(&entry.receipt, &receipt))
                {
                    if entry.progress.published && !entry.progress.undo {
                        Self::read(backend, entry).await
                    } else {
                        Err(uncertain())
                    }
                } else if receipt.binding.retired.load(Ordering::Acquire) {
                    Ok(false)
                } else {
                    Err(mismatch())
                };
                let _ = reply.send(result);
            }
            Command::Progress(reply) => {
                let progress = self
                    .entries
                    .iter()
                    .filter(|entry| !entry.progress.published || entry.progress.undo)
                    .map(|entry| entry.schedule.progress())
                    .chain(profile_progress)
                    .collect();
                let _ = reply.send(Ok(progress));
            }
        }
    }
    async fn read(backend: &LinuxXfrmBackend, entry: &Entry) -> Result<bool, XfrmError> {
        entry.receipt.binding.profile.recheck()?;
        let sa = backend.read_scoped_sa(&entry.request).await?;
        let policy = backend.read_scoped_policy(&entry.request).await?;
        Ok(sa == effect::Readback::Exact && policy == effect::Readback::Exact)
    }
    async fn admit(
        &mut self,
        backend: &LinuxXfrmBackend,
        profile: Option<&LocalXfrmProfile>,
        install: Install,
    ) {
        let Install {
            profile: supplied,
            effect,
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
        if self
            .entries
            .iter()
            .map(|entry| entry.effect.key())
            .any(|key| key.same_request_id(effect.key()) && key.request() != effect.key().request())
        {
            let _ = reply.send(Err(mismatch()));
            return;
        }
        if let Some(entry) = self.entries.iter().find(|entry| {
            entry.effect.key() == effect.key()
                && entry.request.policy.direction == request.policy.direction
        }) {
            let result = if entry.request.sa != request.sa || entry.request.policy != request.policy
            {
                Err(mismatch())
            } else if entry.progress.published && !entry.progress.undo {
                // An exact retry observes a previously published effect, so a
                // store outage cannot revoke it or cause SA reinstallation.
                match Self::read(backend, entry).await {
                    Ok(true) => Ok(entry.receipt.clone()),
                    Ok(false) => Err(uncertain()),
                    Err(error) => Err(error),
                }
            } else {
                Err(uncertain())
            };
            let _ = reply.send(result);
            return;
        }
        let target = match request.policy.direction {
            crate::XfrmDirection::In => LocalEffectUse::XfrmInbound,
            crate::XfrmDirection::Out => LocalEffectUse::XfrmOutbound,
            crate::XfrmDirection::Forward => LocalEffectUse::XfrmForward,
        };
        if effect.consume(target).is_err() {
            let _ = reply.send(Err(mismatch()));
            return;
        }
        self.entries.push(Entry {
            #[cfg(test)]
            fault: self.next_fault.take(),
            effect,
            request,
            receipt: ScopedXfrmReceipt {
                binding: Arc::new(ReceiptBinding {
                    profile: supplied,
                    retired: AtomicBool::new(false),
                }),
            },
            reservation: None,
            guard: Some(guard),
            permit: Some(permit),
            observer: Some(reply),
            remover: None,
            progress: effect::Progress::default(),
            schedule: CleanupSchedule::default(),
        });
    }
    pub(crate) async fn step(&mut self, backend: &LinuxXfrmBackend) {
        let Some(index) = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| !entry.progress.published || entry.progress.undo)
            .min_by_key(|(_, entry)| entry.schedule.next_attempt())
            .filter(|(_, entry)| entry.schedule.next_attempt() <= tokio::time::Instant::now())
            .map(|(index, _)| index)
        else {
            return;
        };
        let entry = &mut self.entries[index];
        let Some(attempt) = entry.schedule.begin() else {
            return;
        };
        if entry
            .observer
            .as_ref()
            .is_some_and(oneshot::Sender::is_closed)
            && !entry.progress.published
        {
            entry.progress.undo = true;
        }
        if !entry.progress.published && entry.effect.recheck_local_execution().is_err() {
            entry.progress.undo = true;
        }
        if entry.guard.is_none() {
            match entry
                .receipt
                .binding
                .profile
                .binding
                .epoch
                .try_begin_operation()
            {
                Ok(Some(guard)) => entry.guard = Some(guard),
                Ok(None) => {
                    entry.schedule.failed(rand::random());
                    return;
                }
                Err(_) => {
                    // Waiting for a conflicting key has made no effect; a
                    // completed intervening reset safely invalidates this wait.
                    if entry.reservation.is_none() {
                        entry.progress.retired = true;
                    } else {
                        entry.schedule.failed(rand::random());
                        return;
                    }
                }
            }
        }
        if !entry.progress.retired && entry.reservation.is_none() {
            if entry.progress.undo {
                entry.progress.retired = true;
            } else {
                match self.registry.reserve(entry.request.clone()) {
                    Ok(reservation) => entry.reservation = Some(reservation),
                    Err(XfrmError::AlreadyExists) => {
                        // No attach ceiling and no retained reset guard while
                        // waiting for another operation's exact retirement.
                        entry.guard = None;
                        entry.schedule.failed(rand::random());
                        return;
                    }
                    Err(_) => {
                        entry.schedule.failed(rand::random());
                        return;
                    }
                }
            }
        }
        if !entry.progress.retired {
            let Some(guard) = entry.guard.as_ref() else {
                return;
            };
            let mut kernel = NativeKernel {
                #[cfg(test)]
                fault: &mut entry.fault,
                backend,
                guard,
                effect: &entry.effect,
                request: &entry.request,
                attempt,
            };
            let progress = &mut entry.progress;
            let observer = &entry.observer;
            let work = async {
                if progress.undo {
                    effect::undo(&mut kernel, progress).await
                } else {
                    effect::install(&mut kernel, progress).await?;
                    effect::publish(&mut kernel, progress, || {
                        observer.as_ref().is_none_or(oneshot::Sender::is_closed)
                    })
                    .await?;
                    #[cfg(test)]
                    kernel.after_publication();
                    Ok(())
                }
            };
            // The future borrows actor-owned intent and pre-mutation flags.
            // Timeout and panic drop only the attempt, never cleanup ownership.
            let result = tokio::time::timeout(
                Duration::from_secs(10),
                AssertUnwindSafe(work).catch_unwind(),
            )
            .await;
            if !matches!(result, Ok(Ok(Ok(())))) {
                if !entry.progress.published {
                    entry.progress.undo = true;
                }
                if entry.progress.undo {
                    entry.schedule.failed(rand::random());
                    return;
                }
                // Publication is irreversible. A later panic only loses the
                // observation; settle it and release the reset guard below.
                if let Some(observer) = entry.observer.take() {
                    let _ = observer.send(Err(uncertain()));
                }
            }
        }
        if entry.progress.retired {
            if let Some(reservation) = &entry.reservation {
                if !self.registry.contains(reservation)
                    || self.registry.retired(reservation).is_err()
                {
                    entry.schedule.failed(rand::random());
                    return;
                }
            }
            let mut entry = self.entries.remove(index);
            entry.receipt.binding.retired.store(true, Ordering::Release);
            if let Some(observer) = entry.observer.take() {
                let _ = observer.send(Err(uncertain()));
            }
            if let Some(remover) = entry.remover.take() {
                let _ = remover.send(Ok(()));
            }
            // Request key buffers, reservation, admission permit and reset
            // guard are dropped only after exact absence was proved.
        } else if entry.progress.published {
            #[cfg(test)]
            if matches!(entry.fault, Some(TestFault::DropPublishedReply)) {
                entry.fault = None;
                entry.observer = None;
            }
            if let Some(observer) = entry.observer.take() {
                let _ = observer.send(Ok(entry.receipt.clone()));
            }
            entry.guard = None;
            entry.permit = None;
        }
    }
}

struct NativeKernel<'a> {
    #[cfg(test)]
    fault: &'a mut Option<TestFault>,
    backend: &'a LinuxXfrmBackend,
    guard: &'a LocalOperation,
    effect: &'a CommittedScopeEffect,
    request: &'a ScopedXfrmRequest,
    attempt: CleanupAttempt,
}
#[cfg(test)]
impl NativeKernel<'_> {
    fn after_publication(&mut self) {
        if matches!(self.fault, Some(TestFault::PanicAfterPublication)) {
            *self.fault = None;
            panic!("injected XFRM panic after publication");
        }
    }
}
#[async_trait::async_trait]
impl effect::Kernel for NativeKernel<'_> {
    fn publication(&self) -> Result<(), XfrmError> {
        self.local()?;
        self.effect
            .recheck_local_execution()
            .map_err(|_| uncertain())
    }
    fn local(&self) -> Result<(), XfrmError> {
        if !self.attempt.has_budget() {
            return Err(uncertain());
        }
        self.guard.recheck().map_err(|_| mismatch())?;
        self.backend.verify_namespace_actor()
    }
    async fn current(&self) -> Result<(), XfrmError> {
        self.local()?;
        if !self.effect.matches_operation(self.guard) {
            return Err(mismatch());
        }
        self.backend.preflight_scoped_sa(self.request)?;
        self.effect.recheck().await.map_err(|_| uncertain())
    }
    async fn policy(&mut self) -> Result<effect::Readback, XfrmError> {
        self.local()?;
        self.backend.read_scoped_policy(self.request).await
    }
    async fn sa(&mut self) -> Result<effect::Readback, XfrmError> {
        self.local()?;
        self.backend.read_scoped_sa(self.request).await
    }
    async fn create_policy(&mut self) -> Result<(), XfrmError> {
        self.local()?;
        let result = self
            .backend
            .install_policy(InstallPolicyRequest {
                parameters: self.request.policy.clone(),
            })
            .await;
        #[cfg(test)]
        if matches!(self.fault, Some(TestFault::PanicAfterPolicy)) {
            *self.fault = None;
            panic!("injected scoped failure after protective policy creation");
        }
        result
    }
    async fn create_sa(&mut self) -> Result<(), XfrmError> {
        self.local()?;
        let result = self
            .backend
            .install_sa(InstallSaRequest {
                parameters: self.request.sa.clone(),
            })
            .await;
        #[cfg(test)]
        match self.fault {
            Some(TestFault::PanicAfterSa) => {
                *self.fault = None;
                panic!("injected scoped failure after candidate SA creation");
            }
            Some(TestFault::PauseAfterSa(pause)) => {
                pause.entered.notify_one();
                pause.resume.notified().await;
                *self.fault = None;
            }
            _ => {}
        }
        result
    }
    async fn remove_sa(&mut self) -> Result<(), XfrmError> {
        self.local()?;
        self.backend
            .remove_scoped_sa(self.request, || self.local())
            .await
    }
    async fn remove_policy(&mut self) -> Result<(), XfrmError> {
        self.local()?;
        self.backend
            .remove_scoped_policy(self.request, || self.local())
            .await
    }
}

#[cfg(test)]
pub(crate) enum TestFault {
    PanicAfterPublication,
    PanicAfterPolicy,
    PanicAfterSa,
    PauseAfterSa(Arc<TestPause>),
    DropPublishedReply,
}
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestPause {
    pub(crate) entered: tokio::sync::Notify,
    pub(crate) resume: tokio::sync::Notify,
}
