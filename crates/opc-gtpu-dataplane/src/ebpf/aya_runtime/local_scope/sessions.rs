//! One namespace actor owns grouped-session intent, reservations and undo.
use super::runtime::Shared;
use super::session_kernel::{mismatch, uncertain, NativeKernel, Request};
use crate::ebpf::local_scope::{session_effect as effect, ScopedGtpuBinding};
use crate::{GtpuError, GtpuSessionGroup, ScopedGtpuReceipt};
use futures_util::FutureExt;
use opc_local_kernel_lifecycle::{
    CleanupProgress, CleanupSchedule, CommittedScopeEffect, LocalEffectUse, LocalInstalledGraph,
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
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit};

pub(super) struct Install {
    pub(super) graph: LocalInstalledGraph,
    pub(super) effect: CommittedScopeEffect,
    pub(super) request: GtpuSessionGroup,
    pub(super) guard: LocalOperation,
    pub(super) permit: OwnedSemaphorePermit,
    pub(super) reply: oneshot::Sender<Result<ScopedGtpuReceipt, GtpuError>>,
}
pub(super) enum Control {
    #[cfg(test)]
    Retained(oneshot::Sender<usize>),
    #[cfg(test)]
    Fault(TestFault, oneshot::Sender<Result<(), GtpuError>>),
    Read {
        receipt: ScopedGtpuReceipt,
        guard: LocalOperation,
        reply: oneshot::Sender<Result<bool, GtpuError>>,
    },
    Remove {
        receipt: ScopedGtpuReceipt,
        guard: LocalOperation,
        reply: oneshot::Sender<Result<(), GtpuError>>,
    },
    Progress(oneshot::Sender<Result<Vec<CleanupProgress>, GtpuError>>),
}
struct Entry {
    #[cfg(test)]
    fault: Option<TestFault>,
    request: Arc<Request>,
    effect: CommittedScopeEffect,
    receipt: ScopedGtpuReceipt,
    guard: Option<LocalOperation>,
    permit: Option<OwnedSemaphorePermit>,
    observer: Option<oneshot::Sender<Result<ScopedGtpuReceipt, GtpuError>>>,
    remover: Option<oneshot::Sender<Result<(), GtpuError>>>,
    reserved: bool,
    progress: effect::Progress,
    schedule: CleanupSchedule,
}
#[derive(Default)]
struct Operations {
    #[cfg(test)]
    next_fault: Option<TestFault>,
    graph: Option<LocalInstalledGraph>,
    entries: Vec<Entry>,
    reservations: Vec<Arc<Request>>,
}
fn same_receipt(first: &ScopedGtpuReceipt, second: &ScopedGtpuReceipt) -> bool {
    Arc::ptr_eq(&first.binding, &second.binding)
}
pub(super) fn start(
    shared: Arc<Shared>,
) -> Result<(mpsc::Sender<Install>, mpsc::Sender<Control>), GtpuError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| uncertain())?;
    let (installs, mut requests) = mpsc::channel(64);
    let (controls, mut commands) = mpsc::channel(64);
    std::thread::Builder::new()
        .name("opc-scoped-gtpu".to_owned())
        .spawn(move || {
            runtime.block_on(async {
                let mut operations = Operations::default();
                let (mut requests_open, mut commands_open) = (true, true);
                loop {
                    let next = operations.next_attempt();
                    if !requests_open && !commands_open && next.is_none() {
                        break;
                    }
                    let deadline = next
                        .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(3600));
                    tokio::select! {
                        biased;
                        command = commands.recv(), if commands_open => match command {
                            Some(command) => operations.control(&shared, command),
                            None => commands_open = false,
                        },
                        () = tokio::time::sleep_until(deadline), if next.is_some() => {},
                        request = requests.recv(), if requests_open => match request {
                            Some(request) => operations.admit(&shared, request),
                            None => requests_open = false,
                        },
                    }
                    if !requests_open && !commands_open {
                        for entry in &mut operations.entries {
                            if !entry.progress.published {
                                entry.progress.undo = true;
                            }
                        }
                    }
                    // Service a due cleanup even under a continuous command stream.
                    // Removing an established session precedes new install work.
                    operations.step(&shared).await;
                }
            });
        })
        .map_err(|_| uncertain())?;
    Ok((installs, controls))
}
impl Operations {
    fn sync_graph(&mut self, graph: &LocalInstalledGraph) -> Result<(), GtpuError> {
        graph.recheck().map_err(|_| mismatch())?;
        if self.graph.as_ref().is_some_and(|old| old.is_same(graph)) {
            return Ok(());
        }
        // A new complete graph can exist only after the common write barrier
        // drained every effect and verified whole-scope retirement. Pending
        // key waiters retained no reservation or reset read guard.
        if self.entries.iter().any(|entry| entry.guard.is_some()) {
            return Err(mismatch());
        }
        for entry in self.entries.drain(..) {
            if let Some(reply) = entry.observer {
                let _ = reply.send(Err(mismatch()));
            }
            if let Some(reply) = entry.remover {
                let _ = reply.send(Err(mismatch()));
            }
        }
        self.reservations.clear();
        self.graph = Some(graph.clone());
        Ok(())
    }
    fn next_attempt(&self) -> Option<tokio::time::Instant> {
        self.entries
            .iter()
            .filter(|entry| !entry.progress.published || entry.progress.undo)
            .map(|entry| entry.schedule.next_attempt())
            .min()
    }
    fn admit(&mut self, shared: &Shared, install: Install) {
        let Install {
            graph,
            effect,
            request,
            guard,
            permit,
            reply,
        } = install;
        if reply.is_closed() {
            return;
        }
        let request = match (|| {
            if guard.recheck().is_err()
                || !effect.matches_operation(&guard)
                || !graph.epoch().is_same(guard.epoch())
            {
                return Err(mismatch());
            }
            let request = Request::new(shared, &graph, request)?;
            self.sync_graph(&graph)?;
            Ok(request)
        })() {
            Ok(request) => Arc::new(request),
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        if self
            .entries
            .iter()
            .map(|entry| entry.effect.key())
            .any(|key| key.same_request_id(effect.key()) && key.request() != effect.key().request())
        {
            let _ = reply.send(Err(mismatch()));
            return;
        }
        if let Some(entry) = self
            .entries
            .iter()
            .find(|entry| entry.effect.key() == effect.key())
        {
            let result = if entry.request.model != request.model {
                Err(mismatch())
            } else if entry.progress.published && !entry.progress.undo {
                Self::read(shared, entry, &guard).and_then(|exact| {
                    if exact {
                        Ok(entry.receipt.clone())
                    } else {
                        Err(uncertain())
                    }
                })
            } else {
                Err(uncertain())
            };
            let _ = reply.send(result);
            return;
        }
        if effect.consume(LocalEffectUse::Gtpu).is_err() {
            let _ = reply.send(Err(mismatch()));
            return;
        }
        self.entries.push(Entry {
            #[cfg(test)]
            fault: self.next_fault.take(),
            request,
            effect,
            receipt: ScopedGtpuReceipt {
                binding: Arc::new(ScopedGtpuBinding {
                    graph,
                    retired: AtomicBool::new(false),
                }),
            },
            guard: Some(guard),
            permit: Some(permit),
            observer: Some(reply),
            remover: None,
            reserved: false,
            progress: effect::Progress::default(),
            schedule: CleanupSchedule::default(),
        });
    }
    fn control(&mut self, shared: &Shared, command: Control) {
        match command {
            #[cfg(test)]
            Control::Retained(reply) => {
                let _ = reply.send(self.entries.len());
            }
            #[cfg(test)]
            Control::Fault(fault, reply) => {
                self.next_fault = Some(fault);
                let _ = reply.send(Ok(()));
            }
            Control::Progress(reply) => {
                let _ = reply.send(Ok(self
                    .entries
                    .iter()
                    .filter(|entry| !entry.progress.published || entry.progress.undo)
                    .map(|entry| entry.schedule.progress())
                    .collect()));
            }
            Control::Read {
                receipt,
                guard,
                reply,
            } => {
                let result = if guard.recheck().is_err()
                    || !guard.epoch().is_same(&receipt.binding.graph.epoch())
                {
                    Err(mismatch())
                } else if receipt.binding.retired.load(Ordering::Acquire) {
                    Ok(false)
                } else if let Some(entry) = self
                    .entries
                    .iter()
                    .find(|entry| same_receipt(&entry.receipt, &receipt))
                {
                    if entry.progress.published && !entry.progress.undo {
                        Self::read(shared, entry, &guard)
                    } else {
                        Err(uncertain())
                    }
                } else {
                    Err(mismatch())
                };
                let _ = reply.send(result);
            }
            Control::Remove {
                receipt,
                guard,
                reply,
            } => {
                if guard.recheck().is_err()
                    || !guard.epoch().is_same(&receipt.binding.graph.epoch())
                {
                    let _ = reply.send(Err(mismatch()));
                } else if receipt.binding.retired.load(Ordering::Acquire) {
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
        }
    }
    fn read(shared: &Shared, entry: &Entry, guard: &LocalOperation) -> Result<bool, GtpuError> {
        let attempt = CleanupSchedule::default().begin().ok_or_else(uncertain)?;
        effect::read_installed(&NativeKernel {
            #[cfg(test)]
            fault: &mut None,
            shared,
            graph: &entry.receipt.binding.graph,
            guard,
            effect: &entry.effect,
            request: &entry.request,
            attempt,
        })
    }
    async fn step(&mut self, shared: &Shared) {
        let Some(index) = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                (!entry.progress.published || entry.progress.undo)
                    && entry.schedule.next_attempt() <= tokio::time::Instant::now()
            })
            .min_by_key(|(_, entry)| (!entry.progress.undo, entry.schedule.next_attempt()))
            .map(|(index, _)| index)
        else {
            return;
        };
        let entry = &mut self.entries[index];
        let Some(attempt) = entry.schedule.begin() else {
            return;
        };
        if !entry.progress.published
            && (entry
                .observer
                .as_ref()
                .is_some_and(oneshot::Sender::is_closed)
                || entry.effect.recheck_local_execution().is_err())
        {
            entry.progress.undo = true;
        }
        if entry.guard.is_none() {
            match entry.receipt.binding.graph.epoch().try_begin_operation() {
                Ok(Some(guard)) => entry.guard = Some(guard),
                Ok(None) => {
                    entry.schedule.failed(rand::random());
                    return;
                }
                Err(_) if !entry.reserved => entry.progress.retired = true,
                Err(_) => {
                    entry.schedule.failed(rand::random());
                    return;
                }
            }
        }
        if !entry.progress.retired && !entry.reserved {
            if entry.progress.undo {
                entry.progress.retired = true;
            } else if self.reservations.iter().any(|old| {
                old.model.id() == entry.request.model.id()
                    || old.indexes.iter().any(|first| {
                        entry
                            .request
                            .indexes
                            .iter()
                            .any(|second| first.key == second.key)
                    })
            }) {
                // Waiting for a key retains bounded admission, but no reset
                // read guard. Control cleanup remains independently admitted.
                entry.guard = None;
                entry.schedule.failed(rand::random());
                return;
            } else {
                self.reservations.push(entry.request.clone());
                entry.reserved = true;
            }
        }
        if !entry.progress.retired {
            let Some(guard) = entry.guard.as_ref() else {
                return;
            };
            let mut kernel = NativeKernel {
                #[cfg(test)]
                fault: &mut entry.fault,
                shared,
                graph: &entry.receipt.binding.graph,
                guard,
                effect: &entry.effect,
                request: &entry.request,
                attempt,
            };
            let work = async {
                if entry.progress.undo {
                    effect::undo(&mut kernel, &mut entry.progress)
                } else {
                    effect::install(&mut kernel, &mut entry.progress).await?;
                    effect::publish(&mut kernel, &mut entry.progress, || {
                        entry
                            .observer
                            .as_ref()
                            .is_none_or(oneshot::Sender::is_closed)
                    })
                    .await?;
                    #[cfg(test)]
                    kernel.after_publication();
                    Ok(())
                }
            };
            if !matches!(
                tokio::time::timeout(
                    Duration::from_secs(10),
                    AssertUnwindSafe(work).catch_unwind()
                )
                .await,
                Ok(Ok(Ok(())))
            ) {
                if !entry.progress.published {
                    entry.progress.undo = true;
                }
                if entry.progress.undo {
                    entry.schedule.failed(rand::random());
                    return;
                }
                // Publication already linearized. Preserve forwarding and
                // release admission/reset guards even when its attempt panics.
                if let Some(reply) = entry.observer.take() {
                    let _ = reply.send(Err(uncertain()));
                }
            }
        }
        if entry.progress.retired {
            let entry = self.entries.swap_remove(index);
            self.reservations
                .retain(|request| !Arc::ptr_eq(request, &entry.request));
            entry.receipt.binding.retired.store(true, Ordering::Release);
            if let Some(reply) = entry.observer {
                let _ = reply.send(Err(uncertain()));
            }
            if let Some(reply) = entry.remover {
                let _ = reply.send(Ok(()));
            }
        } else if entry.progress.published {
            #[cfg(test)]
            if matches!(entry.fault, Some(TestFault::DropPublishedReply)) {
                entry.fault = None;
                entry.observer = None;
            }
            if let Some(reply) = entry.observer.take() {
                let _ = reply.send(Ok(entry.receipt.clone()));
            }
            entry.guard = None;
            entry.permit = None;
        }
    }
}

#[cfg(test)]
pub(in super::super::super) enum TestFault {
    PanicAfterIndex,
    PanicAfterGroup,
    PauseAfterGroup(Arc<TestPause>),
    PanicAfterPublication,
    DropPublishedReply,
}
#[cfg(test)]
#[derive(Default)]
pub(in super::super::super) struct TestPause {
    pub(in super::super::super) entered: tokio::sync::Notify,
    pub(in super::super::super) resume: tokio::sync::Notify,
}
