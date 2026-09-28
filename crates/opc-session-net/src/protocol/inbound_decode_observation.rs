//! Borrowed checkpoints for rejected-input component qualification only.
//!
//! The registry owns numbers, never payloads. A read guard ends before the Vec
//! can grow or move; a decode guard ends before its owner leaves that scope.
//! Parser scratch and partially deserialized fields are outside this slice.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use tokio::runtime::{Handle, RuntimeFlavor};
use tokio::sync::Notify;

use super::SessionConsensusWireRequest;

thread_local! {
    static CURRENT: RefCell<Option<Arc<Observation>>> = const { RefCell::new(None) };
}

/// A currently borrowed allocation's decoding phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    ReadBody,
    DecodeRaw,
    DecodedRequest,
}

/// Numeric evidence read from a real Vec at one borrowed checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Allocation {
    pub(crate) phase: Phase,
    pub(crate) declared: usize,
    pub(crate) address: usize,
    pub(crate) length: usize,
    pub(crate) capacity: usize,
}

/// One simultaneous identity union, not a sum of phase peaks.
#[derive(Clone, Debug)]
pub(crate) struct Snapshot {
    pub(crate) owners: Vec<Allocation>,
    pub(crate) distinct_allocations: usize,
    pub(crate) capacity: usize,
    pub(crate) aliases_agree: bool,
}

impl Snapshot {
    fn from_live(live: &BTreeMap<u64, Allocation>) -> Self {
        let mut distinct = BTreeMap::new();
        let mut aliases_agree = true;
        for owner in live.values().filter(|owner| owner.capacity != 0) {
            if let Some(previous) = distinct.insert(owner.address, owner.capacity) {
                aliases_agree &= previous == owner.capacity;
            }
        }
        Self {
            owners: live.values().copied().collect(),
            distinct_allocations: distinct.len(),
            capacity: distinct.values().sum(),
            aliases_agree,
        }
    }
}

/// Independent reads of the real request Vec, alongside the current registry.
#[derive(Clone, Debug)]
pub(crate) struct RequestSample {
    pub(crate) address: usize,
    pub(crate) length: usize,
    pub(crate) capacity: usize,
    pub(crate) current: Snapshot,
}

/// Independent reads after the actual outer deserializer returned.
#[derive(Clone, Debug)]
pub(crate) struct DecodeSample {
    pub(crate) address: usize,
    pub(crate) length: usize,
    pub(crate) capacity: usize,
    pub(crate) rejected: bool,
    pub(crate) current: Snapshot,
}

/// Bounded evidence retained after all listener tasks have been joined.
#[derive(Clone, Debug)]
pub(crate) struct Report {
    pub(crate) current: Snapshot,
    pub(crate) registered: usize,
    pub(crate) released: usize,
    pub(crate) release_identity_valid: bool,
    pub(crate) last_read_release: Option<Allocation>,
    pub(crate) request_samples: usize,
    pub(crate) request: Option<RequestSample>,
    pub(crate) decode_samples: usize,
    pub(crate) decode: Option<DecodeSample>,
}

struct State {
    live: BTreeMap<u64, Allocation>,
    registered: usize,
    released: usize,
    release_identity_valid: bool,
    last_read_release: Option<Allocation>,
    request_samples: usize,
    request: Option<RequestSample>,
    decode_samples: usize,
    decode: Option<DecodeSample>,
}

/// Current-thread, numeric-only component observer. At most one sample of each
/// decode checkpoint is retained; event counts detect unexpected extra calls.
pub(crate) struct Observation {
    state: Mutex<State>,
    changed: Notify,
}

impl Observation {
    /// Allocate only observer metadata, before any instrumented body read.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                live: BTreeMap::new(),
                registered: 0,
                released: 0,
                release_identity_valid: true,
                last_read_release: None,
                request_samples: 0,
                request: None,
                decode_samples: 0,
                decode: None,
            }),
            changed: Notify::new(),
        })
    }

    /// Read counters without callbacks or an outstanding lock in the caller.
    pub(crate) fn report(&self) -> Report {
        let state = self.state.lock().expect("decode observation");
        Report {
            current: Snapshot::from_live(&state.live),
            registered: state.registered,
            released: state.released,
            release_identity_valid: state.release_identity_valid,
            last_read_release: state.last_read_release,
            request_samples: state.request_samples,
            request: state.request.clone(),
            decode_samples: state.decode_samples,
            decode: state.decode.clone(),
        }
    }

    /// Wait for the real reader to suspend with the requested partial body.
    /// This test-side waiter never delays a listener or changes its deadline.
    pub(crate) async fn wait_for_raw_read(&self, declared: usize, length: usize) -> Allocation {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let owner = {
                let state = self.state.lock().expect("decode observation");
                state
                    .live
                    .values()
                    .find(|owner| {
                        owner.phase == Phase::ReadBody
                            && owner.declared == declared
                            && owner.length == length
                    })
                    .copied()
            };
            if let Some(owner) = owner {
                return owner;
            }
            changed.await;
        }
    }
}

/// This scope cannot cross threads. The runtime check also prevents spawned
/// listener tasks from silently losing a thread-local observer through migration.
pub(crate) struct Scope {
    _current_thread: PhantomData<Rc<()>>,
}

/// Install only on a current-thread Tokio runtime, after client bootstraps.
pub(crate) fn install(observation: &Arc<Observation>) -> Scope {
    assert_eq!(
        Handle::current().runtime_flavor(),
        RuntimeFlavor::CurrentThread,
        "rejected-input observation requires a current-thread runtime"
    );
    CURRENT.with(|current| {
        let mut current = current.borrow_mut();
        assert!(current.is_none(), "decode observation scopes cannot nest");
        *current = Some(Arc::clone(observation));
    });
    Scope {
        _current_thread: PhantomData,
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        CURRENT.with(|current| {
            *current.borrow_mut() = None;
        });
    }
}

fn current() -> Option<Arc<Observation>> {
    CURRENT.with(|current| current.borrow().clone())
}

/// The borrow prevents reallocation/free while this numeric registration exists.
/// Unlike Scope, this guard is Send so the unmodified listener can spawn its task.
pub(crate) struct BorrowedOwner<'a> {
    payload: &'a Vec<u8>,
    observation: Arc<Observation>,
    id: u64,
    phase: Phase,
    declared: usize,
}

fn borrow(payload: &Vec<u8>, phase: Phase, declared: usize) -> Option<BorrowedOwner<'_>> {
    let observation = current()?;
    let allocation = Allocation {
        phase,
        declared,
        address: payload.as_ptr() as usize,
        length: payload.len(),
        capacity: payload.capacity(),
    };
    let id = {
        let mut state = observation.state.lock().expect("decode observation");
        state.registered += 1;
        let id = u64::try_from(state.registered).expect("bounded checkpoint count");
        state.live.insert(id, allocation);
        id
    };
    observation.changed.notify_waiters();
    Some(BorrowedOwner {
        payload,
        observation,
        id,
        phase,
        declared,
    })
}

impl Drop for BorrowedOwner<'_> {
    fn drop(&mut self) {
        let actual = Allocation {
            phase: self.phase,
            declared: self.declared,
            address: self.payload.as_ptr() as usize,
            length: self.payload.len(),
            capacity: self.payload.capacity(),
        };
        {
            let mut state = self.observation.state.lock().expect("decode observation");
            let removed = state.live.remove(&self.id);
            state.release_identity_valid &= removed == Some(actual);
            state.released += 1;
            if self.phase == Phase::ReadBody {
                state.last_read_release = Some(actual);
            }
        }
        self.observation.changed.notify_waiters();
    }
}

/// Borrow exactly while the existing reader awaits the next chunk.
pub(crate) fn borrow_raw_read(payload: &Vec<u8>, declared: usize) -> Option<BorrowedOwner<'_>> {
    borrow(payload, Phase::ReadBody, declared)
}

/// Borrow exactly while the real outer JSON decoder runs.
pub(crate) fn borrow_raw_decode(payload: &Vec<u8>) -> Option<BorrowedOwner<'_>> {
    borrow(payload, Phase::DecodeRaw, payload.len())
}

/// Record direct Vec evidence independently of registration's capacity charge.
pub(crate) fn capture_decode_result(payload: &Vec<u8>, rejected: bool) {
    let Some(observation) = current() else {
        return;
    };
    let address = payload.as_ptr() as usize;
    let length = payload.len();
    let capacity = payload.capacity();
    let mut state = observation.state.lock().expect("decode observation");
    state.decode_samples += 1;
    if state.decode.is_none() {
        state.decode = Some(DecodeSample {
            address,
            length,
            capacity,
            rejected,
            current: Snapshot::from_live(&state.live),
        });
    }
}

/// Delegate unchanged to the derived inner decoder, then borrow its real Vec
/// before it moves into the outer enum. This also runs if a later outer field
/// makes that enum invalid; no partial-deserializer storage is claimed here.
pub(crate) fn deserialize_request<'de, D>(
    deserializer: D,
) -> Result<SessionConsensusWireRequest, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let request = SessionConsensusWireRequest::deserialize(deserializer)?;
    let Some(observation) = current() else {
        return Ok(request);
    };
    let owner = borrow(
        &request.payload,
        Phase::DecodedRequest,
        request.payload.len(),
    );
    // Two actual immutable borrows of one Vec exercise identity union. Neither
    // creates a second payload or extends the request beyond this callback.
    let alias = borrow(
        &request.payload,
        Phase::DecodedRequest,
        request.payload.len(),
    );
    let address = request.payload.as_ptr() as usize;
    let length = request.payload.len();
    let capacity = request.payload.capacity();
    {
        let mut state = observation.state.lock().expect("decode observation");
        state.request_samples += 1;
        if state.request.is_none() {
            state.request = Some(RequestSample {
                address,
                length,
                capacity,
                current: Snapshot::from_live(&state.live),
            });
        }
    }
    drop(alias);
    drop(owner);
    Ok(request)
}
