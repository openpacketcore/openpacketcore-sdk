//! Bounded qualification observations of one exact request per native store.
//!
//! Keys contain scalar slot/generation metadata only. They own no store, task,
//! command, preparation or response. Deactivation censors later events rather
//! than cancelling accepted work. No native path prints or grows the event buffer.

use std::cell::Cell;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use opc_consensus::engine::{Entry, EntryPayload};
use opc_consensus::{ConsensusNodeId, ConsensusRequestId};

use super::storage::ConfigDurableProgress;
use super::ConfigRaftTypeConfig;

const SESSIONS: usize = 9;
const EVENTS: usize = 128;
// Only occurrences of the one selected request are retained, not a log batch.
const INDICES: usize = 8;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    generation: 0,
    slots: [const { None }; SESSIONS],
});

/// An observation of an existing effect boundary, not an acknowledgement API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Immediately before the original client_write_ff await, with its deadline.
    EnqueueStarted,
    /// The original enqueue returned its engine response receiver; index unknown.
    EnqueueAccepted,
    /// This node published its persisted committed frontier; not request-bound.
    CommittedFrontier,
    /// A real storage apply batch includes the exact selected request/index.
    ApplyQueued,
    /// Its existing blocking worker entered, before batch selection/validation.
    ApplyWorkerEntered,
    /// Native apply received the selected transaction prefix containing this index.
    NativeApplyEntered,
    /// The transaction containing this exact request/index returned from commit.
    ApplyTransactionCommitted,
    /// The native result for this index returned to the async storage adapter.
    NativeApplyReturned,
    /// The complete original storage apply is about to return its successful vector.
    StorageApplyReturned,
    /// Openraft returned Ok(Ok(response)); application result/receipt is separate.
    EngineResponseOk,
    /// Openraft returned an engine error; no response index is available.
    EngineResponseError,
    /// The engine response channel closed; no completion is fabricated.
    EngineResponseLost,
    /// Immediately before the existing completion channel send.
    CompletionSending,
    /// The existing channel send accepted the reply; caller polling is unobserved.
    CompletionSent,
    /// The existing channel send found its caller gone.
    CompletionReceiverGone,
}

/// Scalar event; no request identity, payload, receipt or error text is retained.
#[derive(Clone, Copy, Debug)]
pub struct Event {
    /// Elapsed microseconds from the fixture-selected common origin.
    pub at_us: u64,
    /// Actual observed boundary.
    pub phase: Phase,
    /// Actual selected log index, or the frontier for CommittedFrontier.
    pub index: Option<u64>,
    /// Original deadline relative to the same origin, when available.
    pub deadline_us: Option<u64>,
}

/// Detached metadata at deactivation. Missing terminal events remain censored.
#[derive(Debug)]
pub struct Snapshot {
    /// Actual node bound by the store when registering, not a caller-supplied label.
    pub node: ConsensusNodeId,
    /// Cutoff relative to the fixture-selected origin.
    pub cutoff_us: u64,
    /// Events retained in their observation order.
    pub events: Vec<Event>,
    /// Events or selected index occurrences omitted at fixed bounds.
    pub omitted: u64,
}

struct Session {
    core: usize,
    generation: u64,
    node: ConsensusNodeId,
    request: ConsensusRequestId,
    origin: Instant,
    events: Vec<Event>,
    omitted: u64,
}

struct Registry {
    generation: u64,
    slots: [Option<Session>; SESSIONS],
}

fn registry() -> std::sync::MutexGuard<'static, Registry> {
    REGISTRY.lock().unwrap_or_else(|error| error.into_inner())
}

fn micros(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

pub(crate) fn core(progress: &ConfigDurableProgress) -> usize {
    std::ptr::from_ref(progress) as usize
}

/// Qualification registration; dropping it only deactivates observation.
#[must_use]
pub struct Registration<'a> {
    key: Option<Key>,
    // A borrow keeps this metadata address valid without retaining an Arc or
    // engine-storage owner. Copied worker keys have no such lifetime/owner.
    _progress: PhantomData<&'a ConfigDurableProgress>,
}

impl<'a> Registration<'a> {
    pub(crate) fn new(
        progress: &'a ConfigDurableProgress,
        node: ConsensusNodeId,
        request: ConsensusRequestId,
        origin: Instant,
    ) -> Option<Self> {
        let core = core(progress);
        let mut registry = registry();
        if registry
            .slots
            .iter()
            .flatten()
            .any(|entry| entry.core == core)
        {
            return None;
        }
        let slot = registry.slots.iter().position(Option::is_none)?;
        let generation = registry.generation.checked_add(1)?;
        // Allocate before the observed API; no later event grows this Vec.
        let events = Vec::with_capacity(EVENTS);
        registry.generation = generation;
        registry.slots[slot] = Some(Session {
            core,
            generation,
            node,
            request,
            origin,
            events,
            omitted: 0,
        });
        ACTIVE.fetch_add(1, Ordering::Release);
        Some(Self {
            key: Some(Key { slot, generation }),
            _progress: PhantomData,
        })
    }

    /// Stop observation and take its existing bounded metadata buffer.
    /// Returns `None` if this registration no longer has a matching session.
    pub fn finish(mut self) -> Option<Snapshot> {
        let key = self.key.take()?;
        let mut registry = registry();
        let session =
            registry.slots[key.slot].take_if(|session| session.generation == key.generation)?;
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
        Some(Snapshot {
            node: session.node,
            cutoff_us: micros(session.origin.elapsed()),
            events: session.events,
            omitted: session.omitted,
        })
    }
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            let mut registry = registry();
            if registry.slots[key.slot]
                .take_if(|session| session.generation == key.generation)
                .is_some()
            {
                ACTIVE.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Key {
    slot: usize,
    generation: u64,
}

impl Key {
    fn for_core(core: usize) -> Option<Self> {
        if ACTIVE.load(Ordering::Acquire) == 0 {
            return None;
        }
        registry()
            .slots
            .iter()
            .enumerate()
            .find_map(|(slot, entry)| {
                entry
                    .as_ref()
                    .filter(|entry| entry.core == core)
                    .map(|entry| Self {
                        slot,
                        generation: entry.generation,
                    })
            })
    }

    fn request(self) -> Option<ConsensusRequestId> {
        registry().slots[self.slot]
            .as_ref()
            .filter(|session| session.generation == self.generation)
            .map(|session| session.request)
    }

    pub(crate) fn record(
        self,
        phase: Phase,
        index: Option<u64>,
        deadline: Option<tokio::time::Instant>,
    ) {
        let mut registry = registry();
        let Some(session) = registry.slots[self.slot]
            .as_mut()
            .filter(|session| session.generation == self.generation)
        else {
            return;
        };
        if session.events.len() == EVENTS {
            session.omitted = session.omitted.saturating_add(1);
            return;
        }
        session.events.push(Event {
            at_us: micros(session.origin.elapsed()),
            phase,
            index,
            deadline_us: deadline.and_then(|deadline| {
                deadline
                    .into_std()
                    .checked_duration_since(session.origin)
                    .map(micros)
            }),
        });
    }

    fn omit(self) {
        let mut registry = registry();
        if let Some(session) = registry.slots[self.slot]
            .as_mut()
            .filter(|session| session.generation == self.generation)
        {
            session.omitted = session.omitted.saturating_add(1);
        }
    }
}

pub(crate) fn submission(
    progress: &ConfigDurableProgress,
    request: ConsensusRequestId,
    deadline: tokio::time::Instant,
) -> Option<Key> {
    let key = Key::for_core(core(progress))?;
    if key.request()? != request {
        return None;
    }
    key.record(Phase::EnqueueStarted, None, Some(deadline));
    Some(key)
}

pub(crate) fn frontier(progress: &ConfigDurableProgress, index: u64) {
    if let Some(key) = Key::for_core(core(progress)) {
        key.record(Phase::CommittedFrontier, Some(index), None);
    }
}

pub(crate) fn sent<T>(key: Option<Key>, result: Result<(), T>) -> Result<(), T> {
    if let Some(key) = key {
        key.record(
            if result.is_ok() {
                Phase::CompletionSent
            } else {
                Phase::CompletionReceiverGone
            },
            None,
            None,
        );
    }
    result
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Worker {
    key: Key,
    connection: usize,
}

thread_local! { static WORKER: Cell<Option<Worker>> = const { Cell::new(None) }; }

fn worker_key(connection: usize) -> Option<Key> {
    WORKER
        .with(Cell::get)
        .filter(|worker| worker.connection == connection)
        .map(|worker| worker.key)
}

// A thread-local scope must be restored on the same blocking worker thread.
pub(crate) struct WorkerScope(Option<Worker>, PhantomData<std::rc::Rc<()>>);

impl Drop for WorkerScope {
    fn drop(&mut self) {
        WORKER.with(|current| current.set(self.0));
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Batch {
    key: Option<Key>,
    indices: [u64; INDICES],
    len: usize,
}

impl Batch {
    fn empty(key: Option<Key>) -> Self {
        Self {
            key,
            indices: [0; INDICES],
            len: 0,
        }
    }

    fn capture(
        key: Option<Key>,
        requests: impl IntoIterator<Item = (ConsensusRequestId, u64)>,
    ) -> Self {
        let mut batch = Self::empty(key);
        let Some(selected) = key.and_then(Key::request) else {
            return batch;
        };
        for (request, index) in requests {
            if request == selected {
                batch.push(index);
            }
        }
        batch
    }

    fn entries(key: Option<Key>, entries: &[Entry<ConfigRaftTypeConfig>]) -> Self {
        Self::capture(
            key,
            entries.iter().filter_map(|entry| match &entry.payload {
                EntryPayload::Normal(command) => Some((command.request_id, entry.log_id.index)),
                _ => None,
            }),
        )
    }

    fn push(&mut self, index: u64) {
        if self.len == INDICES {
            if let Some(key) = self.key {
                key.omit();
            }
        } else {
            self.indices[self.len] = index;
            self.len += 1;
        }
    }

    fn record(&self, phase: Phase, deadline: Option<tokio::time::Instant>) {
        if let Some(key) = self.key {
            for index in &self.indices[..self.len] {
                key.record(phase, Some(*index), deadline);
            }
        }
    }

    pub(crate) fn enter_worker(&self, conn: &rusqlite::Connection) -> WorkerScope {
        self.enter_worker_id(std::ptr::from_ref(conn) as usize)
    }

    fn enter_worker_id(&self, connection: usize) -> WorkerScope {
        self.record(Phase::ApplyWorkerEntered, None);
        let worker = self.key.map(|key| Worker { key, connection });
        WorkerScope(WORKER.with(|current| current.replace(worker)), PhantomData)
    }

    pub(crate) fn current(
        conn: &rusqlite::Connection,
        entries: &[Entry<ConfigRaftTypeConfig>],
    ) -> Self {
        let batch = Self::entries(worker_key(std::ptr::from_ref(conn) as usize), entries);
        batch.record(Phase::NativeApplyEntered, None);
        batch
    }

    pub(crate) fn committed(&self) {
        self.record(Phase::ApplyTransactionCommitted, None);
    }
}

pub(crate) struct ApplyCall {
    applied: Batch,
}

impl ApplyCall {
    pub(crate) fn new(progress: &ConfigDurableProgress) -> Self {
        Self {
            applied: Batch::empty(Key::for_core(core(progress))),
        }
    }

    pub(crate) fn queued(
        &self,
        entries: &[Entry<ConfigRaftTypeConfig>],
        deadline: tokio::time::Instant,
    ) -> Batch {
        let batch = Batch::entries(self.applied.key, entries);
        batch.record(Phase::ApplyQueued, Some(deadline));
        batch
    }

    pub(crate) fn native_returned(&mut self, batch: &Batch, last_applied: Option<u64>) {
        // A successful native transaction applied the selected contiguous prefix.
        // Use its actual physical frontier, not a cached application response's
        // original index when the engine applies a duplicate request.
        for index in &batch.indices[..batch.len] {
            if last_applied.is_some_and(|last| *index <= last) {
                if let Some(key) = batch.key {
                    key.record(Phase::NativeApplyReturned, Some(*index), None);
                }
                self.applied.push(*index);
            }
        }
    }

    pub(crate) fn returned(&self) {
        self.applied.record(Phase::StorageApplyReturned, None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(value: u64) -> ConsensusNodeId {
        ConsensusNodeId::new(value).unwrap()
    }
    fn request(value: u8) -> ConsensusRequestId {
        ConsensusRequestId::from_bytes([value; 16])
    }

    #[test]
    fn completion_observation_bound_and_generation_censor_late_events() {
        let progress = ConfigDurableProgress::default();
        let origin = Instant::now();
        let first = Registration::new(&progress, node(1), request(1), origin).unwrap();
        assert!(Registration::new(&progress, node(1), request(2), origin).is_none());
        let old = first.key.unwrap();
        let deadline = tokio::time::Instant::from_std(origin + std::time::Duration::from_millis(5));
        old.record(Phase::EnqueueStarted, None, Some(deadline));
        for _ in 0..EVENTS + 2 {
            old.record(Phase::EnqueueAccepted, None, None);
        }
        let snapshot = first.finish().unwrap();
        assert_eq!(snapshot.events[0].deadline_us, Some(5_000));
        assert_eq!(snapshot.events.len(), EVENTS, "fixed event bound");
        assert_eq!(snapshot.events.capacity(), EVENTS, "no event-buffer growth");
        assert_eq!(snapshot.omitted, 3);
        let second = Registration::new(&progress, node(1), request(1), Instant::now()).unwrap();
        old.record(Phase::EngineResponseOk, Some(9), None);
        assert!(
            second.finish().unwrap().events.is_empty(),
            "old generation must not enter a new trace"
        );
        let third = Registration::new(&progress, node(1), request(1), Instant::now()).unwrap();
        Batch::capture(
            third.key,
            (0..INDICES + 2).map(|index| (request(1), index as u64)),
        )
        .record(Phase::ApplyQueued, None);
        let snapshot = third.finish().unwrap();
        assert_eq!(snapshot.events.len(), INDICES, "fixed selected-index bound");
        assert_eq!(snapshot.omitted, 2);
        let fourth = Registration::new(&progress, node(1), request(1), Instant::now()).unwrap();
        drop(fourth);
        assert!(
            Key::for_core(core(&progress)).is_none(),
            "drop must deactivate only this registration"
        );
    }

    #[test]
    fn completion_observation_keeps_exact_request_node_and_index() {
        let progress_a = ConfigDurableProgress::default();
        let progress_b = ConfigDurableProgress::default();
        let first = Registration::new(&progress_a, node(1), request(1), Instant::now()).unwrap();
        let second = Registration::new(&progress_b, node(2), request(1), Instant::now()).unwrap();
        Batch::capture(first.key, [(request(2), 7), (request(1), 9)])
            .record(Phase::ApplyQueued, None);
        Batch::capture(second.key, [(request(1), 17)]).record(Phase::ApplyQueued, None);
        let a = first.finish().unwrap();
        let b = second.finish().unwrap();
        assert_eq!(a.node, node(1));
        assert_eq!(b.node, node(2));
        assert_eq!(
            a.events.iter().map(|event| event.index).collect::<Vec<_>>(),
            [Some(9)],
            "foreign request must not be attributed to selected work"
        );
        assert_eq!(
            b.events.iter().map(|event| event.index).collect::<Vec<_>>(),
            [Some(17)],
            "same request on another node must remain separate"
        );
    }

    #[test]
    fn completion_observation_worker_context_restores_and_deactivates() {
        let progress_a = ConfigDurableProgress::default();
        let progress_b = ConfigDurableProgress::default();
        let first = Registration::new(&progress_a, node(1), request(1), Instant::now()).unwrap();
        let second = Registration::new(&progress_b, node(2), request(2), Instant::now()).unwrap();
        assert_eq!(WORKER.with(Cell::get), None);
        let outer = Batch::capture(first.key, [(request(1), 9)]).enter_worker_id(7);
        assert_eq!(worker_key(7), first.key);
        assert_eq!(
            worker_key(11),
            None,
            "a different connection has no authority"
        );
        {
            let _inner = Batch::capture(second.key, [(request(2), 12)]).enter_worker_id(11);
            assert_eq!(worker_key(11), second.key);
            assert_eq!(worker_key(7), None);
        }
        assert_eq!(worker_key(7), first.key);
        assert_eq!(worker_key(11), None);
        first.finish().unwrap();
        Batch::capture(worker_key(7), [(request(1), 9)]).committed();
        let snapshot = second.finish().unwrap();
        assert!(
            snapshot.events.iter().all(|event| event.index == Some(12)),
            "deactivated worker must not write another node's trace"
        );
        drop(outer);
        assert_eq!(WORKER.with(Cell::get), None);
    }
}
