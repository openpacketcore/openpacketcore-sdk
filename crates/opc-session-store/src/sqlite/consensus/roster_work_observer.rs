//! Test-only work accounting for real, synchronous roster maintenance reads and turns.
//!
//! Native counts include index entries inspected and carriers hydrated. SQLite
//! counts every VM instruction inside the eligibility probe and maintenance turn.
//! Counters are scoped to one configured storage identity on the calling test
//! thread. The direct backend fixtures run synchronous reads and apply there;
//! concurrent fixtures reusing the same synthetic identity must not contribute.

use super::SessionConsensusIdentity;
use rusqlite::Connection;
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static OBSERVERS: Mutex<Vec<Weak<Observation>>> = Mutex::new(Vec::new());
thread_local! {
    static NATIVE: RefCell<Vec<Arc<Observation>>> = const { RefCell::new(Vec::new()) };
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Counts {
    pub(crate) turns: u64,
    pub(crate) probes: u64,
    pub(crate) native_index_entries: u64,
    pub(crate) native_hydrations: u64,
    pub(crate) sqlite_vm_steps: u64,
}

impl Counts {
    pub(crate) fn since(self, before: Self) -> Self {
        Self {
            turns: self.turns - before.turns,
            probes: self.probes - before.probes,
            native_index_entries: self.native_index_entries - before.native_index_entries,
            native_hydrations: self.native_hydrations - before.native_hydrations,
            sqlite_vm_steps: self.sqlite_vm_steps - before.sqlite_vm_steps,
        }
    }
}

struct Observation {
    identity: SessionConsensusIdentity,
    owner_thread: std::thread::ThreadId,
    turns: AtomicU64,
    probes: AtomicU64,
    native_index_entries: AtomicU64,
    native_hydrations: AtomicU64,
    sqlite_vm_steps: AtomicU64,
}

pub(crate) struct WorkObservation(Arc<Observation>);

impl WorkObservation {
    pub(crate) fn new(identity: SessionConsensusIdentity) -> Self {
        let observation = Arc::new(Observation {
            identity,
            owner_thread: std::thread::current().id(),
            turns: AtomicU64::new(0),
            probes: AtomicU64::new(0),
            native_index_entries: AtomicU64::new(0),
            native_hydrations: AtomicU64::new(0),
            sqlite_vm_steps: AtomicU64::new(0),
        });
        OBSERVERS.lock().unwrap().push(Arc::downgrade(&observation));
        ACTIVE.fetch_add(1, Ordering::SeqCst);
        Self(observation)
    }

    pub(crate) fn counts(&self) -> Counts {
        Counts {
            turns: self.0.turns.load(Ordering::SeqCst),
            probes: self.0.probes.load(Ordering::SeqCst),
            native_index_entries: self.0.native_index_entries.load(Ordering::SeqCst),
            native_hydrations: self.0.native_hydrations.load(Ordering::SeqCst),
            sqlite_vm_steps: self.0.sqlite_vm_steps.load(Ordering::SeqCst),
        }
    }
}

impl Drop for WorkObservation {
    fn drop(&mut self) {
        let own = Arc::downgrade(&self.0);
        OBSERVERS
            .lock()
            .unwrap()
            .retain(|observer| !observer.ptr_eq(&own));
        ACTIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

fn matching(identity: SessionConsensusIdentity) -> Vec<Arc<Observation>> {
    if ACTIVE.load(Ordering::Relaxed) == 0 {
        return Vec::new();
    }
    OBSERVERS
        .lock()
        .unwrap()
        .iter()
        .filter_map(Weak::upgrade)
        .filter(|observation| {
            observation.identity == identity
                && observation.owner_thread == std::thread::current().id()
        })
        .collect()
}

pub(crate) struct NativeTurn(Vec<Arc<Observation>>);

pub(crate) fn native_turn(identity: SessionConsensusIdentity) -> NativeTurn {
    native_scope(identity, false)
}

pub(crate) fn native_probe(identity: SessionConsensusIdentity) -> NativeTurn {
    native_scope(identity, true)
}

fn native_scope(identity: SessionConsensusIdentity, probe: bool) -> NativeTurn {
    let observations = matching(identity);
    for observation in &observations {
        let count = if probe {
            &observation.probes
        } else {
            &observation.turns
        };
        count.fetch_add(1, Ordering::SeqCst);
    }
    NativeTurn(NATIVE.with(|current| current.replace(observations)))
}

impl Drop for NativeTurn {
    fn drop(&mut self) {
        NATIVE.with(|current| current.replace(std::mem::take(&mut self.0)));
    }
}

pub(crate) fn native_index_entry() {
    NATIVE.with(|current| {
        for observation in current.borrow().iter() {
            observation
                .native_index_entries
                .fetch_add(1, Ordering::SeqCst);
        }
    });
}

pub(crate) fn native_hydration() {
    NATIVE.with(|current| {
        for observation in current.borrow().iter() {
            observation.native_hydrations.fetch_add(1, Ordering::SeqCst);
        }
    });
}

pub(crate) struct SqliteTurn<'a> {
    connection: &'a Connection,
    probe: bool,
    observations: Vec<Arc<Observation>>,
    steps: Arc<AtomicU64>,
}

pub(crate) fn sqlite_turn(
    connection: &Connection,
    identity: SessionConsensusIdentity,
) -> Option<SqliteTurn<'_>> {
    sqlite_scope(connection, identity, false)
}

pub(crate) fn sqlite_probe(
    connection: &Connection,
    identity: SessionConsensusIdentity,
) -> Option<SqliteTurn<'_>> {
    sqlite_scope(connection, identity, true)
}

fn sqlite_scope(
    connection: &Connection,
    identity: SessionConsensusIdentity,
    probe: bool,
) -> Option<SqliteTurn<'_>> {
    let observations = matching(identity);
    if observations.is_empty() {
        return None;
    }
    let steps = Arc::new(AtomicU64::new(0));
    let recorded = Arc::clone(&steps);
    // The exact consensus eligibility-read and committed-apply paths own this
    // connection lock and install no operation/read/prune progress callback.
    connection
        .progress_handler(
            1,
            Some(move || {
                recorded.fetch_add(1, Ordering::Relaxed);
                false
            }),
        )
        .expect("owned maintenance connection accepts work observation");
    Some(SqliteTurn {
        connection,
        observations,
        steps,
        probe,
    })
}

impl Drop for SqliteTurn<'_> {
    fn drop(&mut self) {
        self.connection
            .progress_handler(0, None::<fn() -> bool>)
            .expect("remove maintenance work observation");
        let steps = self.steps.load(Ordering::Relaxed);
        for observation in &self.observations {
            observation
                .sqlite_vm_steps
                .fetch_add(steps, Ordering::SeqCst);
            let count = if self.probe {
                &observation.probes
            } else {
                &observation.turns
            };
            count.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[test]
fn synchronous_work_observers_do_not_mix_same_identity_across_test_threads() {
    let identity = SessionConsensusIdentity::new(
        crate::consensus::SessionConsensusClusterId::new("roster-work-observer").unwrap(),
        crate::consensus::SessionConsensusConfigurationId::from_bytes([0xD5; 32]),
        crate::consensus::SessionConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let observation = WorkObservation::new(identity);
    let other = std::thread::spawn(move || {
        let observation = WorkObservation::new(identity);
        {
            let _turn = native_turn(identity);
            native_index_entry();
            native_hydration();
        }
        let conn = Connection::open_in_memory().unwrap();
        {
            let _probe = sqlite_probe(&conn, identity).unwrap();
            assert_eq!(
                conn.query_row("SELECT 1", [], |row| row.get::<_, u32>(0))
                    .unwrap(),
                1
            );
        }
        observation.counts()
    })
    .join()
    .unwrap();
    assert_eq!(other.turns, 1);
    assert_eq!(other.probes, 1);
    assert_eq!(other.native_index_entries, 1);
    assert_eq!(other.native_hydrations, 1);
    assert!(other.sqlite_vm_steps > 0);
    assert_eq!(
        observation.counts(),
        Counts::default(),
        "another fixture must not add work"
    );
    {
        let _turn = native_turn(identity);
        native_index_entry();
        native_index_entry();
        native_hydration();
    }
    assert_eq!(
        observation.counts(),
        Counts {
            turns: 1,
            probes: 0,
            native_index_entries: 2,
            native_hydrations: 1,
            sqlite_vm_steps: 0,
        }
    );
}
