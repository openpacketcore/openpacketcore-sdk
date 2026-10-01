//! Opt-in native-I/O observations for the existing eight-operation unit test.
//!
//! Only scalar metadata is retained. A copied key does not own a store, worker,
//! entry, reservation or caller. The synchronous worker context never crosses
//! an await. A fixed event budget is allocated before submission; saturation is
//! reported explicitly. No event prints or grows the buffer on a native path.

use std::cell::Cell;
use std::sync::{LazyLock, Mutex};
use std::time::Instant;
use std::{fmt, io};

use opc_consensus::engine::{Entry, EntryPayload};
use opc_consensus::ConsensusRequestId;

use crate::consensus::ConfigRaftTypeConfig;

const SESSIONS: usize = 8;
const EVENTS: usize = 4_096;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Reason {
    AppendFloor,
    CommittedLineage,
    NativeLimitedRead,
    NativeRangeRead,
    LogStateRead,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Phase {
    TransactionBegin,
    TransactionBegun,
    PointersBegin,
    PointersValidated,
    LastLogBegin,
    LastLogReturned,
    LineageBegin,
    LineageValidated,
    PointerWritten,
    CommitBegin,
    CommitReturned,
    ProgressPublished,
    EntryValidated,
    BatchSized,
    JsonPreflightBegin,
    JsonPreflightReturned,
    CanonicalBegin,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Route {
    Legacy,
    Canonical,
    Fallback,
}

#[derive(Clone, Copy, Debug)]
enum Outcome {
    Completed,
    TimedOut,
    Failed(io::ErrorKind),
    Cancelled,
    Unfinished,
    Unwound,
}

#[derive(Clone, Copy, Debug, Default)]
struct Totals {
    encoded_rows: usize,
    encoded_bytes: usize,
    selected_rows: usize,
    selected_bytes: usize,
    decoded_rows: usize,
    returned_rows: usize,
    returned_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
enum Detail {
    Queued {
        start: Option<u64>,
        end: Option<u64>,
        entries: Option<usize>,
    },
    WorkerEntered,
    Phase(Phase),
    Encoded {
        index: u64,
        request: u8,
        bytes: usize,
    },
    RowBegin {
        index: u64,
        bytes: usize,
    },
    RowDecoded {
        index: u64,
        request: u8,
    },
    RowReturned {
        index: u64,
        bytes: Option<usize>,
    },
    CanonicalSpan {
        encoded_bytes: usize,
        decoded_bytes: usize,
    },
    Route(Route),
    EntriesReturned {
        count: usize,
        first: Option<u64>,
        last: Option<u64>,
    },
    WorkerBodyReturned {
        outcome: Outcome,
        totals: Totals,
    },
    CallerReturned(Outcome),
}

#[derive(Clone, Copy)]
struct Key {
    slot: usize,
    generation: u64,
    operation: u64,
    started: Instant,
    reason: Reason,
}

struct Event {
    operation: u64,
    reason: Reason,
    elapsed_us: u128,
    operation_us: u128,
    detail: Detail,
}

struct Session {
    generation: u64,
    origin: Instant,
    requests: [ConsensusRequestId; 8],
    operations: u64,
    events: Vec<Event>,
    omitted: usize,
}

struct Registry {
    generation: u64,
    sessions: [Option<Session>; SESSIONS],
}

static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| {
    Mutex::new(Registry {
        generation: 0,
        sessions: std::array::from_fn(|_| None),
    })
});

#[derive(Clone, Copy)]
struct Worker {
    key: Key,
    totals: Totals,
    last_row: Option<(u64, usize)>,
}

thread_local! {
    static CURRENT: Cell<Option<Worker>> = const { Cell::new(None) };
}

fn session_mut(registry: &mut Registry, key: Key) -> Option<&mut Session> {
    registry.sessions[key.slot]
        .as_mut()
        .filter(|session| session.generation == key.generation)
}

fn record(key: Option<Key>, make: impl FnOnce(&Session) -> Detail) {
    let Some(key) = key else { return };
    let mut registry = REGISTRY.lock().expect("native diagnostic registry");
    let Some(session) = session_mut(&mut registry, key) else {
        return;
    };
    if session.events.len() == EVENTS {
        session.omitted = session.omitted.saturating_add(1);
        return;
    }
    let now = Instant::now();
    let detail = make(session);
    session.events.push(Event {
        operation: key.operation,
        reason: key.reason,
        elapsed_us: now.duration_since(session.origin).as_micros(),
        operation_us: now.duration_since(key.started).as_micros(),
        detail,
    });
}

fn request_ordinal(session: &Session, entry: &Entry<ConfigRaftTypeConfig>) -> u8 {
    let EntryPayload::Normal(command) = &entry.payload else {
        return 0;
    };
    session
        .requests
        .iter()
        .position(|request| *request == command.request_id)
        .map_or(0, |index| (index + 1) as u8)
}

fn current_key() -> Option<Key> {
    CURRENT.with(|current| current.get().map(|worker| worker.key))
}

/// Registration is owned by the fixture, independently of every native owner.
/// Its drop also preserves the bounded trace when an earlier assertion fails.
pub(crate) struct Registration {
    slot: usize,
    generation: u64,
    active: bool,
}

impl Registration {
    pub(crate) fn new(origin: Instant, requests: [ConsensusRequestId; 8]) -> Self {
        let mut registry = REGISTRY.lock().expect("native diagnostic registry");
        assert!(!registry
            .sessions
            .iter()
            .flatten()
            .any(|value| value.origin == origin));
        let slot = registry
            .sessions
            .iter()
            .position(Option::is_none)
            .expect("bounded native diagnostic sessions");
        registry.generation = registry
            .generation
            .checked_add(1)
            .expect("diagnostic generation");
        let generation = registry.generation;
        registry.sessions[slot] = Some(Session {
            generation,
            origin,
            requests,
            operations: 0,
            events: Vec::with_capacity(EVENTS),
            omitted: 0,
        });
        Self {
            slot,
            generation,
            active: true,
        }
    }

    pub(crate) fn finish(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let session = {
            let mut registry = REGISTRY.lock().expect("native diagnostic registry");
            assert_eq!(
                registry.sessions[self.slot].as_ref().map(|s| s.generation),
                Some(self.generation)
            );
            registry.sessions[self.slot]
                .take()
                .expect("registered native diagnostic")
        };
        // Detach before output. No native task waits for diagnostic formatting
        // or stdout; events after this cutoff are intentionally unobserved.
        println!(
            "CONFIG_CAPACITY_NATIVE_IO_CUTOFF store={} events={} omitted={} operations={} elapsed_us={}",
            session.generation,
            session.events.len(),
            session.omitted,
            session.operations,
            session.origin.elapsed().as_micros()
        );
        for event in session.events {
            println!(
                "CONFIG_CAPACITY_NATIVE_IO store={} op={} reason={:?} elapsed_us={} operation_us={} {}",
                session.generation,
                event.operation, event.reason, event.elapsed_us, event.operation_us, event.detail
            );
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.finish();
    }
}

/// The async guard describes the caller only, never the lifetime of native work.
pub(crate) struct Call {
    key: Option<Key>,
    returned: bool,
}

impl Call {
    pub(crate) fn queued(
        origin: Option<Instant>,
        reason: Reason,
        start: Option<u64>,
        end: Option<u64>,
        entries: Option<usize>,
    ) -> Self {
        let key = origin.and_then(|origin| {
            let mut registry = REGISTRY.lock().expect("native diagnostic registry");
            let (slot, session) =
                registry
                    .sessions
                    .iter_mut()
                    .enumerate()
                    .find_map(|(slot, session)| {
                        session
                            .as_mut()
                            .filter(|s| s.origin == origin)
                            .map(|s| (slot, s))
                    })?;
            session.operations = session
                .operations
                .checked_add(1)
                .expect("diagnostic operation count");
            Some(Key {
                slot,
                generation: session.generation,
                operation: session.operations,
                started: Instant::now(),
                reason,
            })
        });
        record(key, |_| Detail::Queued {
            start,
            end,
            entries,
        });
        Self {
            key,
            returned: false,
        }
    }

    pub(crate) fn worker(&self) -> WorkerToken {
        WorkerToken(self.key)
    }

    pub(crate) fn completed(&mut self) {
        self.returned = true;
        record(self.key, |_| Detail::CallerReturned(Outcome::Completed));
    }

    pub(crate) fn failed(&mut self, error: &io::Error) {
        self.returned = true;
        record(self.key, |_| Detail::CallerReturned(failure(error.kind())));
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        if !self.returned {
            record(self.key, |_| {
                Detail::CallerReturned(if std::thread::panicking() {
                    Outcome::Unwound
                } else {
                    Outcome::Cancelled
                })
            });
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct WorkerToken(Option<Key>);

pub(crate) struct Scope {
    previous: Option<Worker>,
    outcome: Outcome,
}

impl Scope {
    pub(crate) fn enter(token: WorkerToken) -> Self {
        let worker = token.0.map(|key| Worker {
            key,
            totals: Totals::default(),
            last_row: None,
        });
        let previous = CURRENT.with(|current| current.replace(worker));
        record(token.0, |_| Detail::WorkerEntered);
        Self {
            previous,
            outcome: Outcome::Unfinished,
        }
    }

    pub(crate) fn completed(&mut self) {
        self.outcome = Outcome::Completed;
    }
    pub(crate) fn failed(&mut self, error: &io::Error) {
        self.failed_kind(error.kind());
    }
    pub(crate) fn failed_kind(&mut self, kind: io::ErrorKind) {
        self.outcome = failure(kind);
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let worker = CURRENT.with(|current| current.replace(self.previous));
        if let Some(worker) = worker {
            let outcome = if std::thread::panicking() {
                Outcome::Unwound
            } else {
                self.outcome
            };
            record(Some(worker.key), |_| Detail::WorkerBodyReturned {
                outcome,
                totals: worker.totals,
            });
        }
    }
}

fn failure(kind: io::ErrorKind) -> Outcome {
    if kind == io::ErrorKind::TimedOut {
        Outcome::TimedOut
    } else {
        Outcome::Failed(kind)
    }
}

pub(crate) fn phase(phase: Phase) {
    record(current_key(), |_| Detail::Phase(phase));
}
pub(crate) fn route(route: Route) {
    record(current_key(), |_| Detail::Route(route));
}
pub(crate) fn canonical_span(encoded_bytes: usize, decoded_bytes: usize) {
    record(current_key(), |_| Detail::CanonicalSpan {
        encoded_bytes,
        decoded_bytes,
    });
}
pub(crate) fn encoded(entry: &Entry<ConfigRaftTypeConfig>, bytes: usize) {
    CURRENT.with(|current| {
        if let Some(mut worker) = current.get() {
            worker.totals.encoded_rows += 1;
            worker.totals.encoded_bytes = worker.totals.encoded_bytes.saturating_add(bytes);
            current.set(Some(worker));
            record(Some(worker.key), |session| Detail::Encoded {
                index: entry.log_id.index,
                request: request_ordinal(session, entry),
                bytes,
            });
        }
    });
}

pub(crate) fn row_begin(index: u64, bytes: usize) {
    CURRENT.with(|current| {
        if let Some(mut worker) = current.get() {
            worker.totals.selected_rows += 1;
            worker.totals.selected_bytes = worker.totals.selected_bytes.saturating_add(bytes);
            worker.last_row = Some((index, bytes));
            current.set(Some(worker));
            record(Some(worker.key), |_| Detail::RowBegin { index, bytes });
        }
    });
}
pub(crate) fn row_decoded(entry: &Entry<ConfigRaftTypeConfig>) {
    CURRENT.with(|current| {
        if let Some(mut worker) = current.get() {
            worker.totals.decoded_rows += 1;
            current.set(Some(worker));
            record(Some(worker.key), |session| Detail::RowDecoded {
                index: entry.log_id.index,
                request: request_ordinal(session, entry),
            });
        }
    });
}
pub(crate) fn row_returned(entry: &Entry<ConfigRaftTypeConfig>) {
    CURRENT.with(|current| {
        if let Some(mut worker) = current.get() {
            let bytes = worker
                .last_row
                .filter(|(index, _)| *index == entry.log_id.index)
                .map(|(_, bytes)| bytes);
            worker.totals.returned_rows += 1;
            worker.totals.returned_bytes = worker
                .totals
                .returned_bytes
                .saturating_add(bytes.unwrap_or(0));
            current.set(Some(worker));
            record(Some(worker.key), |_| Detail::RowReturned {
                index: entry.log_id.index,
                bytes,
            });
        }
    });
}
pub(crate) fn entries_returned(entries: &[Entry<ConfigRaftTypeConfig>]) {
    record(current_key(), |_| Detail::EntriesReturned {
        count: entries.len(),
        first: entries.first().map(|entry| entry.log_id.index),
        last: entries.last().map(|entry| entry.log_id.index),
    });
}

// Spell out scalar fields: Debug-derived field reads do not satisfy dead-code
// checks, and a format implementation prevents ever formatting native errors.
impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed => f.write_str("completed"),
            Self::TimedOut => f.write_str("timed_out"),
            Self::Failed(kind) => write!(f, "failed({kind:?})"),
            Self::Cancelled => f.write_str("cancelled"),
            Self::Unfinished => f.write_str("unfinished"),
            Self::Unwound => f.write_str("unwound"),
        }
    }
}

impl fmt::Display for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Queued { start, end, entries } => write!(f, "queued start={start:?} end_exclusive={end:?} entries={entries:?}"),
            Self::WorkerEntered => f.write_str("worker_body_entered"),
            Self::Phase(phase) => write!(f, "phase={phase:?}"),
            Self::Encoded { index, request, bytes } => write!(f, "encoded index={index} request_ordinal={request} bytes={bytes}"),
            Self::RowBegin { index, bytes } => write!(f, "row_begin index={index} bytes={bytes}"),
            Self::RowDecoded { index, request } => write!(f, "row_decoded index={index} request_ordinal={request}"),
            Self::RowReturned { index, bytes } => write!(f, "row_returned index={index} bytes={bytes:?}"),
            Self::CanonicalSpan { encoded_bytes, decoded_bytes } => write!(f, "canonical_span encoded_bytes={encoded_bytes} decoded_bytes={decoded_bytes}"),
            Self::Route(route) => write!(f, "route={route:?}"),
            Self::EntriesReturned { count, first, last } => write!(f, "entries_returned count={count} first={first:?} last={last:?}"),
            Self::WorkerBodyReturned { outcome, totals } => write!(f, "worker_body_returned outcome={outcome} encoded_rows={} encoded_bytes={} selected_rows={} selected_bytes={} decoded_rows={} returned_rows={} returned_bytes={}", totals.encoded_rows, totals.encoded_bytes, totals.selected_rows, totals.selected_bytes, totals.decoded_rows, totals.returned_rows, totals.returned_bytes),
            Self::CallerReturned(outcome) => write!(f, "caller_returned outcome={outcome}"),
        }
    }
}
