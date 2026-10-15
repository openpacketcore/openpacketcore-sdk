//! Test-only election inputs for the unchanged Openraft engine and Tokio clock.
//!
//! Scripts are scoped to one node's construction and inherited by its engine
//! tasks. Unscripted tasks use Tokio's ordinary random number generator. The
//! feature is not enabled by production dependencies.

use std::collections::VecDeque;
use std::future::Future;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openraft::{AsyncRuntime, OptionalSend, TokioRuntime};
use rand_08::RngCore;
use tokio::sync::watch;
use tokio::time::Instant;

tokio::task_local! {
    static ELECTION_SCRIPT: ElectionRngScript;
}

struct ScriptState {
    active: AtomicBool,
    samples: Mutex<VecDeque<u64>>,
    draws: Mutex<Vec<(Instant, u64)>>,
    sleeps: watch::Sender<Vec<(Instant, Instant)>>,
}

/// A finite sequence of raw RNG samples for one node, including resampling.
#[derive(Clone)]
pub struct ElectionRngScript(Arc<ScriptState>);

impl ElectionRngScript {
    /// Use these samples with the engine's own `gen_range` implementation.
    pub fn new(samples: impl IntoIterator<Item = u64>) -> Self {
        Self(Arc::new(ScriptState {
            active: AtomicBool::new(true),
            samples: Mutex::new(samples.into_iter().collect()),
            draws: Mutex::new(Vec::new()),
            sleeps: watch::channel(Vec::new()).0,
        }))
    }

    /// Construct a node in this scope so its engine tasks inherit the script.
    pub async fn scope<F: Future>(&self, future: F) -> F::Output {
        ELECTION_SCRIPT.scope(self.clone(), future).await
    }

    /// Samples consumed so far, with their protocol-clock instants.
    pub fn draws(&self) -> Vec<(Instant, u64)> {
        self.0
            .draws
            .lock()
            .expect("election sample observations")
            .clone()
    }

    /// Observe sleep registration without changing its deadline or completion.
    pub fn sleeps(&self) -> watch::Receiver<Vec<(Instant, Instant)>> {
        self.0.sleeps.subscribe()
    }

    /// Fail if a planned campaign or resampling step did not occur.
    pub fn assert_exhausted(&self) {
        assert!(
            self.0.samples.lock().expect("election samples").is_empty(),
            "election RNG script was not exhausted"
        );
    }

    /// Finish the controlled phase, returning later campaigns to Tokio's RNG.
    pub fn finish(&self) {
        self.assert_exhausted();
        self.0.active.store(false, Ordering::SeqCst);
    }

    fn next_sample(&self) -> u64 {
        let sample = self
            .0
            .samples
            .lock()
            .expect("election samples")
            .pop_front()
            .expect("unexpected election RNG sample");
        self.0
            .draws
            .lock()
            .expect("election sample observations")
            .push((Instant::now(), sample));
        sample
    }

    fn observe_sleep(&self, deadline: Instant) {
        self.0.sleeps.send_modify(|sleeps| {
            sleeps.push((Instant::now(), deadline));
        });
    }
}

/// A scoped sample source, falling back to Tokio's RNG outside a script.
pub struct ElectionRng {
    script: Option<ElectionRngScript>,
    ordinary: <TokioRuntime as AsyncRuntime>::ThreadLocalRng,
}

impl RngCore for ElectionRng {
    fn next_u32(&mut self) -> u32 {
        match &self.script {
            Some(script) => script.next_sample() as u32,
            None => self.ordinary.next_u32(),
        }
    }

    fn next_u64(&mut self) -> u64 {
        match &self.script {
            Some(script) => script.next_sample(),
            None => self.ordinary.next_u64(),
        }
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        if self.script.is_none() {
            self.ordinary.fill_bytes(destination);
            return;
        }
        for chunk in destination.chunks_mut(size_of::<u64>()) {
            let sample = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&sample[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_08::Error> {
        if self.script.is_none() {
            return self.ordinary.try_fill_bytes(destination);
        }
        self.fill_bytes(destination);
        Ok(())
    }
}

/// Tokio's runtime behavior with explicitly scoped election RNG inputs.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ScriptedElectionRuntime;

impl AsyncRuntime for ScriptedElectionRuntime {
    type JoinError = <TokioRuntime as AsyncRuntime>::JoinError;
    type JoinHandle<T: OptionalSend + 'static> = <TokioRuntime as AsyncRuntime>::JoinHandle<T>;
    type Sleep = <TokioRuntime as AsyncRuntime>::Sleep;
    type Instant = <TokioRuntime as AsyncRuntime>::Instant;
    type TimeoutError = <TokioRuntime as AsyncRuntime>::TimeoutError;
    type Timeout<R, T: Future<Output = R> + OptionalSend> =
        <TokioRuntime as AsyncRuntime>::Timeout<R, T>;
    type ThreadLocalRng = ElectionRng;
    type OneshotSender<T: OptionalSend> = <TokioRuntime as AsyncRuntime>::OneshotSender<T>;
    type OneshotReceiverError = <TokioRuntime as AsyncRuntime>::OneshotReceiverError;
    type OneshotReceiver<T: OptionalSend> = <TokioRuntime as AsyncRuntime>::OneshotReceiver<T>;

    fn spawn<T>(future: T) -> Self::JoinHandle<T::Output>
    where
        T: Future + OptionalSend + 'static,
        T::Output: OptionalSend + 'static,
    {
        match ELECTION_SCRIPT.try_with(Clone::clone) {
            Ok(script) => TokioRuntime::spawn(ELECTION_SCRIPT.scope(script, future)),
            Err(_) => TokioRuntime::spawn(future),
        }
    }

    fn sleep(duration: Duration) -> Self::Sleep {
        let _ = ELECTION_SCRIPT.try_with(|script| script.observe_sleep(Instant::now() + duration));
        TokioRuntime::sleep(duration)
    }

    fn sleep_until(deadline: Self::Instant) -> Self::Sleep {
        let _ = ELECTION_SCRIPT.try_with(|script| script.observe_sleep(deadline));
        TokioRuntime::sleep_until(deadline)
    }

    fn timeout<R, F: Future<Output = R> + OptionalSend>(
        duration: Duration,
        future: F,
    ) -> Self::Timeout<R, F> {
        TokioRuntime::timeout(duration, future)
    }

    fn timeout_at<R, F: Future<Output = R> + OptionalSend>(
        deadline: Self::Instant,
        future: F,
    ) -> Self::Timeout<R, F> {
        TokioRuntime::timeout_at(deadline, future)
    }

    fn is_panic(join_error: &Self::JoinError) -> bool {
        TokioRuntime::is_panic(join_error)
    }

    fn thread_rng() -> Self::ThreadLocalRng {
        ElectionRng {
            script: ELECTION_SCRIPT
                .try_with(Clone::clone)
                .ok()
                .filter(|script| script.0.active.load(Ordering::SeqCst)),
            ordinary: TokioRuntime::thread_rng(),
        }
    }

    fn oneshot<T>() -> (Self::OneshotSender<T>, Self::OneshotReceiver<T>)
    where
        T: OptionalSend,
    {
        TokioRuntime::oneshot()
    }
}
