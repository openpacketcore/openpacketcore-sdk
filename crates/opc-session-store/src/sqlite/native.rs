//! Private native backend dispatch. Every selected read enters the same WAL
//! owner as application before any SQL connection or reader-lane admission.

use super::*;
use consensus::wal::Wal;
use std::io;

#[cfg(test)]
pub(crate) mod startup_pressure;

/// A startup-owned, real-monotonic delay for contended authority reads.
///
/// A timer descriptor wakes the reactor even when Tokio time is paused. The
/// caller's existing absolute RPC deadline still bounds the enclosing future;
/// cancelling a wait leaves no worker or retry task. Concurrent callers share
/// timer expiries but each retains its own real-time minimum. The descriptor
/// is prepared before storage opens and is disarmed when no caller is waiting.
pub(crate) struct AuthorityBackoff {
    timer: tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
    waiters: std::sync::Mutex<usize>,
}

struct AuthorityWaitGuard<'a>(&'a AuthorityBackoff);

impl Drop for AuthorityWaitGuard<'_> {
    fn drop(&mut self) {
        let mut waiters = self
            .0
            .waiters
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *waiters -= 1;
        if *waiters == 0 {
            // No background task or idle timer activity survives the last
            // completed/cancelled waiter. The next caller arms a fresh tick.
            let _ = self.0.set_active(false);
        }
    }
}

impl AuthorityBackoff {
    pub(super) fn new() -> io::Result<Self> {
        #[cfg(test)]
        let _pressure = startup_pressure::take();
        let timer = rustix::time::timerfd_create(
            rustix::time::TimerfdClockId::Monotonic,
            rustix::time::TimerfdFlags::NONBLOCK | rustix::time::TimerfdFlags::CLOEXEC,
        )?;
        Ok(Self {
            timer: tokio::io::unix::AsyncFd::with_interest(timer, tokio::io::Interest::READABLE)?,
            waiters: std::sync::Mutex::new(0),
        })
    }

    fn set_active(&self, active: bool) -> io::Result<()> {
        let interval = rustix::time::Timespec {
            tv_sec: 0,
            tv_nsec: if active { 1_000_000 } else { 0 },
        };
        rustix::time::timerfd_settime(
            self.timer.get_ref(),
            rustix::time::TimerfdTimerFlags::empty(),
            &rustix::time::Itimerspec {
                it_interval: interval,
                it_value: interval,
            },
        )?;
        Ok(())
    }

    pub(super) async fn wait(&self) -> io::Result<()> {
        self.wait_with_clock(std::time::Instant::now).await
    }

    async fn wait_with_clock(&self, now: impl Fn() -> std::time::Instant) -> io::Result<()> {
        let deadline = now() + Duration::from_millis(1);
        let _waiter = {
            let mut waiters = self
                .waiters
                .lock()
                .map_err(|_| io::Error::other("authority backoff state unavailable"))?;
            if *waiters == 0 {
                self.set_active(true)?;
            }
            *waiters += 1;
            AuthorityWaitGuard(self)
        };
        loop {
            // AsyncFd::readable registers each future in the reactor's waiter
            // list. One tick wakes the cohort, without serial one-ms waits or
            // any lock held across await. Only the first reader drains the fd.
            let mut ready = self.timer.readable().await?;
            match ready.try_io(|timer| {
                let mut expirations = [0_u8; 8];
                rustix::io::read(timer.get_ref(), &mut expirations).map_err(io::Error::from)
            }) {
                Ok(Ok(8)) => {
                    ready.clear_ready();
                }
                Ok(Ok(_)) => return Err(io::Error::other("incomplete authority backoff timer")),
                Ok(Err(error)) => return Err(error),
                // Another notified waiter may have drained this same tick.
                Err(_) => {}
            }
            // A late joiner or stale readiness after cancellation must still
            // wait its own full interval. The next shared tick serves it;
            // adding callers does not add one interval per predecessor.
            if now() >= deadline {
                return Ok(());
            }
        }
    }
}

pub(super) fn unavailable() -> StoreError {
    StoreError::BackendUnavailable("native session state is unavailable".into())
}

impl SqliteSessionBackend {
    /// Prepare fixed-quorum resources before selecting or reopening storage.
    pub(crate) fn new_authority_backoff(&self) -> io::Result<Option<Arc<AuthorityBackoff>>> {
        // A pristine fixed root is selected later by storage admission.
        // Testing native_enabled here would miss that required allocation.
        let native = self.native_owner.is_some();
        #[cfg(test)]
        let native = self
            .private_wal_test
            .as_ref()
            .map_or(native, |test| test.is_native());
        native
            .then(|| AuthorityBackoff::new().map(Arc::new))
            .transpose()
    }

    pub(super) fn native_enabled(&self) -> bool {
        #[cfg(test)]
        if self
            .private_wal_test
            .as_ref()
            .is_some_and(|backend| backend.is_native())
        {
            return true;
        }
        self.native_owner
            .as_ref()
            .is_some_and(|owner| owner.selected())
    }

    fn native_current(&self) -> Result<Arc<Wal>, StoreError> {
        #[cfg(test)]
        if let Some(test) = self
            .private_wal_test
            .as_ref()
            .filter(|test| test.is_native())
        {
            return test.current().map_err(|_| unavailable());
        }
        self.native_owner
            .as_ref()
            .filter(|owner| owner.selected())
            .ok_or_else(unavailable)?
            .current()
            .map_err(|_| unavailable())
    }

    /// Acquire the existing store-wide worker permit before spawning. A
    /// dropped caller cancels its queued closure; an active worker retains
    /// its permit and immutable capture until its checked work finishes.
    pub(super) async fn native_read_task<T, F>(&self, read: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(
                &crate::consensus::native::NativeState,
                &dyn Fn() -> io::Result<()>,
            ) -> Result<T, StoreError>
            + Send
            + 'static,
    {
        let deadline = tokio::time::Instant::now()
            .checked_add(SQLITE_OPERATION_MAX_WORK)
            .ok_or_else(unavailable)?;
        self.native_read_task_at(deadline, Arc::clone(&self.operation_workers), read)
            .await
    }

    pub(super) async fn native_read_task_at<T, F>(
        &self,
        deadline: tokio::time::Instant,
        workers: Arc<tokio::sync::Semaphore>,
        read: F,
    ) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(
                &crate::consensus::native::NativeState,
                &dyn Fn() -> io::Result<()>,
            ) -> Result<T, StoreError>
            + Send
            + 'static,
    {
        let permit = tokio::time::timeout_at(deadline, workers.acquire_owned())
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
        let wal = self.native_current()?;
        let cancellation = Arc::new(AtomicBool::new(false));
        let task_cancellation = Arc::clone(&cancellation);
        let operation_deadline = deadline.into_std();
        let queued = Arc::new(StdMutex::new(Some((permit, wal, read))));
        let task_queued = Arc::clone(&queued);
        let task = tokio::task::spawn_blocking(move || {
            let (_permit, wal, read) = task_queued
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()?;
            let check = || {
                if task_cancellation.load(Ordering::Acquire)
                    || std::time::Instant::now() >= operation_deadline
                {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "native read work budget exhausted",
                    ))
                } else {
                    Ok(())
                }
            };
            Some(
                wal.native_public_read(&check, read)
                    .map_err(|_| unavailable())
                    .and_then(|result| result),
            )
        });
        let mut cancel_on_drop = RestoreScanCancellation {
            cancellation,
            abort: task.abort_handle(),
            armed: true,
            cancel_queued: Some(Box::new(move || {
                drop(
                    queued
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take(),
                );
            })),
        };
        match tokio::time::timeout_at(deadline, task).await {
            Err(_) => Err(unavailable()),
            Ok(completed) => {
                cancel_on_drop.disarm();
                completed
                    .map_err(|_| unavailable())?
                    .ok_or_else(unavailable)?
            }
        }
    }

    pub(super) fn native_read<T>(
        &self,
        read: impl FnOnce(&Wal) -> io::Result<T>,
    ) -> Option<io::Result<T>> {
        self.native_enabled().then(|| {
            self.native_current()
                .map_err(|_| io::Error::other("native owner unavailable"))
                .and_then(|wal| read(&wal))
        })
    }

    pub(super) fn native_v2_mutation_snapshot(
        &self,
        acceptance: &FixedQuorumActivatedV2MutationSnapshotRequest,
    ) -> Option<Result<FixedQuorumActivatedV2MutationSnapshot, StoreError>> {
        self.native_read(|wal| {
            #[cfg(test)]
            if self
                .consensus_operator_recovery_failure
                .load(Ordering::Acquire)
                || self
                    .fixed_quorum_v2_mutation_snapshot_cut
                    .load(Ordering::Acquire)
            {
                return Err(io::Error::other("native injected authority failure"));
            }
            wal.native_fixed_read(
                crate::sqlite::consensus::wal::native::FixedReadExpectation {
                    identity: acceptance.storage_identity,
                    members: &acceptance.expected_members,
                    bindings: &acceptance.expected_bindings,
                    placement: acceptance.expected_placement_policy,
                    pristine: false,
                    database_path: self.database_path.as_deref().map(PathBuf::as_path),
                },
                |state, exact| {
                    if !exact
                        || acceptance.storage_identity != acceptance.scope_identity
                        || acceptance.voters != acceptance.expected_members
                    {
                        return Err(io::Error::other("native fixed authority differs"));
                    }
                    Ok(
                        if state.v2_activation_matches(
                            acceptance.scope_identity,
                            &acceptance.voters,
                            acceptance.profile_digest,
                        ) {
                            FixedQuorumActivatedV2MutationSnapshot::Activated {
                                applied_logical_time: state.logical_time(),
                            }
                        } else {
                            FixedQuorumActivatedV2MutationSnapshot::Unactivated
                        },
                    )
                },
            )
        })
        .map(|result| result.map_err(|_| unavailable()))
    }

    pub(super) fn native_v2_status_batch(
        &self,
        acceptance: &FixedQuorumFencedTransitionV2StatusReadRequest,
        requests: &[crate::FencedTransitionV2Request],
    ) -> Option<Result<FixedQuorumFencedTransitionV2StatusBatchRead, StoreError>> {
        self.native_read(|wal| {
            if requests.is_empty() {
                return Err(io::Error::other("native status cohort unavailable"));
            }
            #[cfg(test)]
            if self
                .consensus_operator_recovery_failure
                .load(Ordering::Acquire)
            {
                return Err(io::Error::other("native status cohort unavailable"));
            }
            wal.native_fixed_receipt_read(
                crate::sqlite::consensus::wal::native::FixedReadExpectation {
                    identity: acceptance.storage_identity,
                    members: &acceptance.expected_members,
                    bindings: &acceptance.expected_bindings,
                    placement: acceptance.expected_placement_policy,
                    pristine: false,
                    database_path: self.database_path.as_deref().map(PathBuf::as_path),
                },
                requests,
                |state, exact, receipts| {
                    if !exact
                        || acceptance.storage_identity != acceptance.scope_identity
                        || acceptance.voters != acceptance.expected_members
                    {
                        return Err(io::Error::other("native fixed status authority differs"));
                    }
                    if acceptance.require_activation
                        && !state.v2_activation_matches(
                            acceptance.scope_identity,
                            &acceptance.voters,
                            acceptance.profile_digest,
                        )
                    {
                        return Ok(Ok(
                            FixedQuorumFencedTransitionV2StatusBatchRead::Unactivated,
                        ));
                    }
                    Ok(requests
                        .iter()
                        .map(|request| match receipts {
                            Some(receipts) => state.status_with_receipts(request, receipts),
                            None => state.status(request),
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .map(FixedQuorumFencedTransitionV2StatusBatchRead::Activated))
                },
            )
        })
        .map(|result| result.map_err(|_| unavailable())?)
    }
}

#[cfg(test)]
mod authority_backoff_tests {
    use super::*;

    fn assert_idle(backoff: &AuthorityBackoff) {
        assert_eq!(*backoff.waiters.lock().unwrap(), 0);
        let timer = rustix::time::timerfd_gettime(backoff.timer.get_ref()).unwrap();
        assert_eq!(timer.it_interval, rustix::time::Timespec::default());
        assert_eq!(timer.it_value, rustix::time::Timespec::default());
    }

    #[derive(Default)]
    struct WakeCount {
        parent: futures_util::task::AtomicWaker,
        wakes: std::sync::atomic::AtomicUsize,
    }

    impl futures_util::task::ArcWake for WakeCount {
        fn wake_by_ref(counter: &Arc<Self>) {
            counter.wakes.fetch_add(1, Ordering::SeqCst);
            counter.parent.wake();
        }
    }

    fn count_wakes<F: std::future::Future>(
        future: F,
    ) -> (impl std::future::Future<Output = F::Output>, Arc<WakeCount>) {
        let counter = Arc::new(WakeCount::default());
        let observed = Arc::clone(&counter);
        let mut future = Box::pin(future);
        let counted = std::future::poll_fn(move |context| {
            observed.parent.register(context.waker());
            let waker = futures_util::task::waker_ref(&observed);
            future
                .as_mut()
                .poll(&mut std::task::Context::from_waker(&waker))
        });
        (counted, counter)
    }

    #[tokio::test]
    async fn concurrent_authority_waits_share_an_expiry() {
        let backoff = AuthorityBackoff::new().expect("startup timer");
        let mut waits = (0..128)
            .map(|_| Box::pin(backoff.wait()))
            .collect::<Vec<_>>();
        for wait in &mut waits {
            assert!(futures_util::poll!(wait.as_mut()).is_pending());
        }
        let results = tokio::time::timeout(
            Duration::from_millis(64),
            futures_util::future::join_all(waits),
        )
        .await
        .expect("128 concurrent waits must not queue 128 one-millisecond intervals");
        assert_eq!(results.len(), 128);
        assert!(results.iter().all(Result::is_ok));
        assert_idle(&backoff);
    }

    async fn pulse_shared_expiry(backoff: &AuthorityBackoff) {
        rustix::time::timerfd_settime(
            backoff.timer.get_ref(),
            rustix::time::TimerfdTimerFlags::empty(),
            &rustix::time::Itimerspec {
                it_interval: rustix::time::Timespec::default(),
                it_value: rustix::time::Timespec {
                    tv_sec: 0,
                    tv_nsec: 1,
                },
            },
        )
        .expect("deliver one shared timer expiry");
        // Observe readiness without consuming it: the registered waiters must
        // process this same real timer event through the production wait loop.
        let mut ready = tokio::time::timeout(Duration::from_secs(1), backoff.timer.readable())
            .await
            .expect("shared timer becomes readable")
            .expect("shared timer readiness");
        ready.retain_ready();
    }

    #[tokio::test]
    async fn late_authority_waiter_honours_its_full_minimum_delay() {
        let backoff = AuthorityBackoff::new().expect("startup timer");
        let origin = std::time::Instant::now();
        let now = std::cell::Cell::new(origin);
        let mut early = Box::pin(backoff.wait_with_clock(|| now.get()));
        assert!(futures_util::poll!(early.as_mut()).is_pending());
        // Control tick delivery separately from the minimum-delay clock. Host
        // scheduling can delay a pulse, but cannot satisfy a waiter's minimum.
        backoff
            .set_active(false)
            .expect("control shared timer ticks");

        let joined = origin + Duration::from_micros(900);
        now.set(joined);
        let late_clock_reads = std::cell::Cell::new(0);
        let mut late = Box::pin(backoff.wait_with_clock(|| {
            late_clock_reads.set(late_clock_reads.get() + 1);
            now.get()
        }));
        assert!(futures_util::poll!(late.as_mut()).is_pending());
        assert_eq!(*backoff.waiters.lock().unwrap(), 2);
        assert_eq!(late_clock_reads.get(), 1);

        now.set(origin + Duration::from_millis(1));
        pulse_shared_expiry(&backoff).await;
        assert!(matches!(
            futures_util::poll!(early.as_mut()),
            std::task::Poll::Ready(Ok(()))
        ));
        assert!(
            futures_util::poll!(late.as_mut()).is_pending(),
            "a late joiner must not finish with the earlier cohort"
        );
        assert!(
            late_clock_reads.get() > 1,
            "the late joiner must have processed the shared expiry"
        );
        assert_eq!(*backoff.waiters.lock().unwrap(), 1);

        let deadline = joined + Duration::from_millis(1);
        now.set(deadline - Duration::from_nanos(1));
        let reads_before = late_clock_reads.get();
        pulse_shared_expiry(&backoff).await;
        assert!(
            futures_util::poll!(late.as_mut()).is_pending(),
            "the late joiner must wait its entire one-millisecond minimum"
        );
        assert!(late_clock_reads.get() > reads_before);
        now.set(deadline);
        pulse_shared_expiry(&backoff).await;
        assert!(matches!(
            futures_util::poll!(late.as_mut()),
            std::task::Poll::Ready(Ok(()))
        ));
        assert_idle(&backoff);
    }

    #[tokio::test]
    async fn concurrent_authority_waiters_do_not_spin() {
        let backoff = AuthorityBackoff::new().expect("startup timer");
        let started = std::time::Instant::now();
        let (waits, counts): (Vec<_>, Vec<_>) = (0..16)
            .map(|_| {
                count_wakes(async {
                    loop {
                        backoff.wait().await.expect("shared timer wait");
                        if started.elapsed() >= Duration::from_millis(100) {
                            break;
                        }
                    }
                })
            })
            .unzip();
        tokio::time::timeout(
            Duration::from_secs(1),
            futures_util::future::join_all(waits),
        )
        .await
        .expect("all concurrent timer waits finish");
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(100));
        for (index, count) in counts.iter().enumerate() {
            let wakes = count.wakes.load(Ordering::SeqCst);
            assert!(wakes > 0, "waiter {index} actually waits for a wake");
            assert!(
                wakes as u128 <= elapsed.as_micros() / 250 + 4,
                "waiter {index} must stay below 4,000 wakes per second: {wakes} in {elapsed:?}"
            );
        }
        assert_idle(&backoff);
    }

    #[tokio::test]
    async fn cancelling_the_active_authority_wait_preserves_a_fresh_delay() {
        let backoff = AuthorityBackoff::new().expect("startup timer");
        for iteration in 0..32 {
            let mut cancelled = Box::pin(backoff.wait());
            assert!(futures_util::poll!(cancelled.as_mut()).is_pending());
            if iteration % 2 == 0 {
                std::thread::sleep(Duration::from_millis(3));
            }
            drop(cancelled);
            assert_idle(&backoff);
            let started = std::time::Instant::now();
            tokio::time::timeout(Duration::from_millis(40), backoff.wait())
                .await
                .expect("cancelled holder must not strand the next waiter")
                .expect("fresh delay after holder cancellation");
            assert!(
                started.elapsed() >= Duration::from_millis(1),
                "expired or stale readiness must not bypass the next waiter's delay"
            );
            assert_idle(&backoff);
        }
    }

    #[tokio::test]
    async fn cancelling_a_queued_authority_wait_preserves_the_next_waiter() {
        let backoff = AuthorityBackoff::new().expect("startup timer");
        let mut occupied = Box::pin(backoff.wait());
        assert!(futures_util::poll!(occupied.as_mut()).is_pending());
        let mut cancelled = Box::pin(backoff.wait());
        let mut next = Box::pin(backoff.wait());
        assert!(futures_util::poll!(cancelled.as_mut()).is_pending());
        assert!(futures_util::poll!(next.as_mut()).is_pending());
        drop(cancelled);
        drop(occupied);
        tokio::time::timeout(Duration::from_millis(40), &mut next)
            .await
            .expect("cancellation cannot strand another caller")
            .expect("remaining caller receives its real timer wake");
        assert!(
            backoff.waiters.try_lock().is_ok(),
            "completed wait releases admission"
        );
        assert_idle(&backoff);
    }
}
