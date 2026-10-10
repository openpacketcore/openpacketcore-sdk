use super::*;

impl LocalRebuildGuard {
    /// Run one backend's fresh structural loader on an owning namespace thread.
    ///
    /// The loader checks `observer_closed` before publishing through `complete`.
    /// It retains its successfully built runtime before returning. A dropped
    /// observer cannot abandon partial hooks or pins: any failed/unpublished
    /// attempt runs exact contained retirement until verified, with backoff.
    /// Loaded links must be inert on drop; ordinary Aya auto-detach links are
    /// inappropriate for an identity-checked shared lifecycle.
    pub async fn supervise<T: Send + 'static>(
        self,
        build: impl FnOnce(&LocalRebuildGuard, &dyn Fn() -> bool) -> Result<T, Error> + Send + 'static,
    ) -> Result<T, Error> {
        self.recheck()?;
        let watch = self.watch.clone();
        let (reply, observed) = oneshot::channel();
        std::thread::Builder::new()
            .name("opc-local-build".to_owned())
            .spawn(move || {
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
                    let initial = watch
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .begin();
                    *self
                        .attempt
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = initial;
                    let result = if reply.is_closed() {
                        Err(Error::Indeterminate)
                    } else {
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            build(&self, &|| reply.is_closed())
                        }))
                        .unwrap_or(Err(Error::Indeterminate))
                    };
                    let published = self
                        .binding
                        .lifecycle
                        .inner
                        .state
                        .lock()
                        .map_err(|_| Error::Indeterminate)
                        .map(|state| state.graphs.contains_key(&self.binding.index));
                    if matches!(published, Ok(true)) {
                        // Complete local publication survives a lost reply or a
                        // later loader panic. Reset is the only retirement path.
                        let _ = reply.send(result);
                        return;
                    }
                    // Never report success from a loader that omitted complete.
                    drop(result);
                    loop {
                        let next = {
                            let mut schedule = watch
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            schedule.failed(rand::random());
                            schedule.next_attempt()
                        };
                        tokio::time::sleep_until(next).await;
                        *self
                            .attempt
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = watch
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .begin();
                        let retired =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                self.retire_partial()
                            }));
                        if matches!(retired, Ok(Ok(()))) {
                            let _ = reply.send(Err(Error::Indeterminate));
                            break;
                        }
                    }
                });
            })
            .map_err(|_| Error::Indeterminate)?;
        observed.await.map_err(|_| Error::Indeterminate)?
    }
}

impl Drop for LocalRebuildGuard {
    fn drop(&mut self) {
        let Some(barrier) = self.barrier.take() else {
            return;
        };
        let pending = self
            .binding
            .lifecycle
            .inner
            .state
            .lock()
            .map_or(true, |state| {
                state.epoch == self.epoch
                    && state.rebuilding.contains(&self.binding.index)
                    && !state.graphs.contains_key(&self.binding.index)
            });
        if !pending {
            return;
        }
        let (binding, epoch, contained, watch) = (
            self.binding.clone(),
            self.epoch,
            self.contained.clone(),
            self.watch.clone(),
        );
        // Keep the work recoverable until the thread actually takes it. If
        // thread creation fails, the dropping caller retains responsibility.
        let work = Arc::new(Mutex::new(Some(move || {
            let guard = LocalRebuildGuard {
                binding,
                epoch,
                contained,
                barrier: Some(barrier),
                attempt: Mutex::new(None),
                watch,
            };
            loop {
                let next = {
                    let mut schedule = guard
                        .watch
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    schedule.failed(rand::random());
                    schedule.next_attempt()
                };
                std::thread::sleep(next.saturating_duration_since(tokio::time::Instant::now()));
                *guard
                    .attempt
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = guard
                    .watch
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .begin();
                let retired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    guard.retire_partial()
                }));
                if matches!(retired, Ok(Ok(()))) {
                    break;
                }
            }
        })));
        let worker = work.clone();
        let started = std::thread::Builder::new()
            .name("opc-local-abandoned-build".to_owned())
            .spawn(move || {
                let job = worker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(job) = job {
                    job();
                }
            });
        if started.is_err() {
            let job = work
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(job) = job {
                job();
            }
        }
    }
}
