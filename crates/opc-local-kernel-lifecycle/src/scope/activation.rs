use super::*;
use crate::{opening, CommittedScopeEffect, EffectKey};
use futures_util::FutureExt;
use opc_linux_gtpu_sys::tc::InstalledArtifact;

struct CompletionBinding {
    epoch: LocalScopeEpoch,
    key: EffectKey,
    contained: ContainedScope,
    identity: Arc<()>,
}
// The coordinator retains publication facts without retaining itself through
// a completion's epoch. An outside completion retains the lifecycle normally.
#[derive(Clone)]
pub(super) struct PublishedOpening {
    key: EffectKey,
    identity: Arc<()>,
}

/// A published activation-bound opening with no steady-state containment
/// filters. Dropping the completion never tears down established forwarding.
#[derive(Clone)]
pub struct KernelCompletion {
    binding: Arc<CompletionBinding>,
}
impl std::fmt::Debug for KernelCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KernelCompletion")
    }
}
impl KernelCompletion {
    /// The exact committed activation whose opening was published.
    pub fn key(&self) -> &EffectKey {
        &self.binding.key
    }
    /// Passive local readback. Store outages do not expire this publication.
    pub fn recheck(&self) -> Result<(), Error> {
        self.binding.epoch.recheck()?;
        let lifecycle = &self.binding.epoch.lifecycle;
        let graphs = {
            let state = lifecycle
                .inner
                .state
                .lock()
                .map_err(|_| Error::Indeterminate)?;
            if state
                .opened
                .as_ref()
                .is_none_or(|opened| !Arc::ptr_eq(&opened.identity, &self.binding.identity))
            {
                return Err(Error::Stale);
            }
            complete_graphs(lifecycle, &state)?
        };
        let refs = graphs.iter().map(Arc::as_ref).collect::<Vec<_>>();
        if !self.binding.contained.opening_is_complete(&refs)? {
            return Err(Error::Indeterminate);
        }
        self.binding.epoch.recheck()
    }
}

fn complete_graphs(
    lifecycle: &LocalKernelLifecycle,
    state: &State,
) -> Result<Vec<Arc<InstalledArtifact>>, Error> {
    if !state.rebuilding.is_empty() || state.graphs.len() != lifecycle.inner.artifacts.len() {
        return Err(Error::Incomplete(ResetPhase::Artifacts));
    }
    (0..lifecycle.inner.artifacts.len())
        .map(|index| {
            state
                .graphs
                .get(&index)
                .cloned()
                .ok_or(Error::Incomplete(ResetPhase::Artifacts))
        })
        .collect()
}

impl LocalKernelLifecycle {
    /// Open a fully rebuilt scope under this exact committed activation.
    ///
    /// The consumer first finishes the required session/SA effects. Every
    /// filter removal rechecks current execution and the complete graph. Once
    /// admitted, a namespace thread owns the operation through publication or
    /// verified re-containment, including cancellation, panic and lost replies.
    /// An exact published retry performs only local readback, even offline.
    pub async fn open(
        &self,
        reset: &LocalScopeResetReceipt,
        effect: CommittedScopeEffect,
    ) -> Result<KernelCompletion, Error> {
        if !Arc::ptr_eq(&self.inner, &reset.lifecycle.inner) {
            return Err(Error::Stale);
        }
        self.local_scope().verify()?;
        let serial = self.inner.opening.clone().lock_owned().await;
        let epoch = LocalScopeEpoch {
            lifecycle: self.clone(),
            epoch: reset.epoch,
        };
        let guard = epoch.begin_operation().await?;
        if !effect.matches_operation(&guard) {
            return Err(Error::Stale);
        }
        let (graphs, previous) = {
            let state = self.inner.state.lock().map_err(|_| Error::Indeterminate)?;
            (complete_graphs(self, &state)?, state.opened.clone())
        };
        if let Some(previous) = previous {
            if &previous.key != effect.key() {
                return Err(Error::Stale);
            }
            let previous = KernelCompletion {
                binding: Arc::new(CompletionBinding {
                    epoch,
                    key: previous.key,
                    contained: reset.contained.clone(),
                    identity: previous.identity,
                }),
            };
            previous.recheck()?;
            return Ok(previous);
        }
        reset.contained.recheck()?;
        let completion = KernelCompletion {
            binding: Arc::new(CompletionBinding {
                epoch,
                key: effect.key().clone(),
                contained: reset.contained.clone(),
                identity: Arc::new(()),
            }),
        };
        let watch = self.cleanup_watch()?;
        let lifecycle = self.clone();
        #[cfg(all(test, target_os = "linux"))]
        let mut fault = self
            .inner
            .open_fault
            .lock()
            .map_err(|_| Error::Indeterminate)?
            .take();
        let (reply, observed) = oneshot::channel();
        std::thread::Builder::new()
            .name("opc-local-open".to_owned())
            .spawn(move || {
                let _serial = serial;
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(_) => {
                        let _ = reply.send(Err(Error::Indeterminate));
                        return;
                    }
                };
                runtime.block_on(async {
                    let mut progress = opening::Progress::default();
                    loop {
                        let next = watch
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .next_attempt();
                        tokio::time::sleep_until(next).await;
                        let Some(attempt) = watch
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .begin()
                        else {
                            continue;
                        };
                        let mut port = NativeOpen {
                            lifecycle: &lifecycle,
                            guard: &guard,
                            effect: &effect,
                            graphs: &graphs,
                            completion: &completion,
                            attempt,
                            #[cfg(all(test, target_os = "linux"))]
                            fault: &mut fault,
                        };
                        let work = async {
                            opening::bounded_attempt(&mut port, &mut progress, || {
                                reply.is_closed()
                            })
                            .await?;
                            #[cfg(all(test, target_os = "linux"))]
                            port.after_publication(progress.published);
                            Ok::<(), Error>(())
                        };
                        let outcome = std::panic::AssertUnwindSafe(work).catch_unwind().await;
                        if matches!(outcome, Ok(Ok(()))) {
                            #[cfg(all(test, target_os = "linux"))]
                            if matches!(fault, Some(TestFault::DropReply)) {
                                break;
                            }
                            let result = if progress.published {
                                Ok(completion)
                            } else {
                                Err(progress.failure.unwrap_or(Error::Indeterminate))
                            };
                            let _ = reply.send(result);
                            break;
                        }
                        if progress.published {
                            // A failed observation cannot undo an irreversible
                            // publication or keep the shared reset guard occupied.
                            let _ = reply.send(Err(Error::Indeterminate));
                            break;
                        }
                        // Intent and the reset barrier stay outside the dropped
                        // attempt. From the first failure onward, only closure runs.
                        progress.failed(Error::Indeterminate);
                        watch
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .failed(rand::random());
                    }
                });
            })
            .map_err(|_| Error::Indeterminate)?;
        observed.await.map_err(|_| Error::Indeterminate)?
    }
}

struct NativeOpen<'a> {
    #[cfg(all(test, target_os = "linux"))]
    fault: &'a mut Option<TestFault>,
    lifecycle: &'a LocalKernelLifecycle,
    guard: &'a LocalOperation,
    effect: &'a CommittedScopeEffect,
    graphs: &'a [Arc<InstalledArtifact>],
    completion: &'a KernelCompletion,
    attempt: crate::CleanupAttempt,
}
impl NativeOpen<'_> {
    fn graph_refs(&self) -> Vec<&InstalledArtifact> {
        self.graphs.iter().map(Arc::as_ref).collect()
    }
}
#[async_trait]
impl opening::Port for NativeOpen<'_> {
    async fn current(&self) -> Result<(), Error> {
        self.local()?;
        self.effect.recheck().await.map_err(|_| Error::Stale)
    }
    fn local(&self) -> Result<(), Error> {
        if !self.attempt.has_budget() {
            return Err(Error::OpeningAttemptExpired);
        }
        if !self.effect.matches_operation(self.guard) {
            return Err(Error::Stale);
        }
        self.guard.recheck()
    }
    fn publication(&mut self) -> Result<(), Error> {
        self.local()?;
        self.effect
            .recheck_local_execution()
            .map_err(|_| Error::Stale)?;
        let mut state = self
            .lifecycle
            .inner
            .state
            .lock()
            .map_err(|_| Error::Indeterminate)?;
        if state.opened.is_some() {
            return Err(Error::Stale);
        }
        state.opened = Some(PublishedOpening {
            key: self.completion.key().clone(),
            identity: self.completion.binding.identity.clone(),
        });
        Ok(())
    }
    fn covered(&self) -> Result<(), Error> {
        self.completion
            .binding
            .contained
            .recheck()
            .map_err(Into::into)
    }
    fn open_next(&mut self) -> Result<bool, Error> {
        self.local()?;
        self.lifecycle
            .inner
            .layout
            .verify(self.lifecycle.local_scope())?;
        for artifact in &self.lifecycle.inner.artifacts {
            artifact.inspect(self.lifecycle.local_scope())?;
        }
        let complete = self
            .completion
            .binding
            .contained
            .open_next(&self.graph_refs())?;
        #[cfg(all(test, target_os = "linux"))]
        if !complete {
            self.after_delete()?;
        }
        Ok(complete)
    }
    fn is_open(&self) -> Result<bool, Error> {
        self.local()?;
        self.completion
            .binding
            .contained
            .opening_is_complete(&self.graph_refs())
            .map_err(Into::into)
    }
    fn contain(&mut self) -> Result<(), Error> {
        #[cfg(all(test, target_os = "linux"))]
        if matches!(self.fault, Some(TestFault::HoldClosure(_))) {
            if let Some(TestFault::HoldClosure(pause)) = self.fault.take() {
                pause.wait();
            }
        }
        self.local()?;
        self.lifecycle
            .local_scope()
            .contain()?
            .recheck()
            .map_err(Into::into)
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(super) enum TestFault {
    AttemptExpiredAfterDelete,
    LostAck(usize),
    PanicAfterDelete(usize),
    PauseAfterDelete(Arc<TestPause>),
    LostAckHoldClosure(Arc<TestPause>),
    HoldClosure(Arc<TestPause>),
    PanicAfterPublication,
    DropReply,
}
#[cfg(all(test, target_os = "linux"))]
#[derive(Default)]
pub(super) struct TestPause {
    pub(super) entered: tokio::sync::Notify,
    resumed: Mutex<bool>,
    condition: std::sync::Condvar,
}
#[cfg(all(test, target_os = "linux"))]
impl TestPause {
    pub(super) fn resume(&self) {
        *self.resumed.lock().unwrap() = true;
        self.condition.notify_one();
    }
    fn wait(&self) {
        self.entered.notify_one();
        let resumed = self
            .condition
            .wait_while(self.resumed.lock().unwrap(), |resumed| !*resumed)
            .unwrap();
        assert!(*resumed, "native opening fixture was not resumed");
    }
}
#[cfg(all(test, target_os = "linux"))]
impl NativeOpen<'_> {
    fn after_delete(&mut self) -> Result<(), Error> {
        match self.fault {
            Some(TestFault::LostAck(left) | TestFault::PanicAfterDelete(left)) if *left > 1 => {
                *left -= 1;
                return Ok(());
            }
            Some(
                TestFault::AttemptExpiredAfterDelete
                | TestFault::LostAck(_)
                | TestFault::PanicAfterDelete(_)
                | TestFault::PauseAfterDelete(_)
                | TestFault::LostAckHoldClosure(_),
            ) => {}
            _ => return Ok(()),
        }
        match self.fault.take().unwrap() {
            TestFault::AttemptExpiredAfterDelete => Err(Error::Scope(
                opc_linux_gtpu_sys::tc::ScopeError::AttemptExpired,
            )),
            TestFault::LostAck(_) => Err(Error::Indeterminate),
            TestFault::PanicAfterDelete(_) => {
                panic!("injected opening panic after real filter removal")
            }
            TestFault::PauseAfterDelete(pause) => {
                pause.wait();
                Ok(())
            }
            TestFault::LostAckHoldClosure(pause) => {
                *self.fault = Some(TestFault::HoldClosure(pause));
                Err(Error::Indeterminate)
            }
            _ => unreachable!(),
        }
    }
    fn after_publication(&mut self, published: bool) {
        if published && matches!(self.fault, Some(TestFault::PanicAfterPublication)) {
            *self.fault = None;
            panic!("injected opening panic after publication");
        }
    }
}
