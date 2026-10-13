//! Test-only, scope-bound observations across the real WAL and Raft threads.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use super::{Entry, EntryPayload, SessionMutationIntent, SessionRaftTypeConfig};
use crate::scope_authority::ScopeId;

static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static OBSERVERS: Mutex<Vec<Weak<Observation>>> = Mutex::new(Vec::new());

#[derive(Clone, Default, Debug, serde::Serialize)]
pub(crate) struct Counts {
    pub(crate) decodes: BTreeMap<u64, usize>,
    pub(crate) final_audits: BTreeMap<u64, usize>,
}

impl Counts {
    pub(crate) fn since(&self, previous: &Self) -> Self {
        fn difference(
            current: &BTreeMap<u64, usize>,
            previous: &BTreeMap<u64, usize>,
        ) -> BTreeMap<u64, usize> {
            current
                .iter()
                .filter_map(|(&index, &count)| {
                    let count = count - previous.get(&index).copied().unwrap_or(0);
                    (count != 0).then_some((index, count))
                })
                .collect()
        }
        Self {
            decodes: difference(&self.decodes, &previous.decodes),
            final_audits: difference(&self.final_audits, &previous.final_audits),
        }
    }
}

struct Observation {
    scope: ScopeId,
    minimum_bytes: usize,
    counts: Mutex<Counts>,
}

pub(crate) struct PayloadDecodeObservation(Arc<Observation>);

impl PayloadDecodeObservation {
    pub(crate) fn new(scope: ScopeId, minimum_bytes: usize) -> Self {
        let observation = Arc::new(Observation {
            scope,
            minimum_bytes,
            counts: Mutex::new(Counts::default()),
        });
        OBSERVERS.lock().unwrap().push(Arc::downgrade(&observation));
        ACTIVE.fetch_add(1, Ordering::SeqCst);
        Self(observation)
    }

    pub(crate) fn counts(&self) -> Counts {
        self.0.counts.lock().unwrap().clone()
    }
}

impl Drop for PayloadDecodeObservation {
    fn drop(&mut self) {
        let own = Arc::downgrade(&self.0);
        OBSERVERS
            .lock()
            .unwrap()
            .retain(|observer| !observer.ptr_eq(&own));
        ACTIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(crate) fn decoded(entry: &Entry<SessionRaftTypeConfig>, bytes: usize) {
    record(entry, bytes, false);
}

pub(crate) fn final_audit(entry: &Entry<SessionRaftTypeConfig>, bytes: usize) {
    record(entry, bytes, true);
}

fn record(entry: &Entry<SessionRaftTypeConfig>, bytes: usize, final_audit: bool) {
    if ACTIVE.load(Ordering::Relaxed) == 0 {
        return;
    }
    let EntryPayload::Normal(command) = &entry.payload else {
        return;
    };
    let intent = match &command.intent {
        SessionMutationIntent::Authorized { mutation, .. } => mutation.as_ref(),
        intent => intent,
    };
    let SessionMutationIntent::ScopeBatch(command) = intent else {
        return;
    };
    let observers = OBSERVERS.lock().unwrap();
    for observer in observers.iter().filter_map(Weak::upgrade) {
        if observer.scope != *command.request.scope() || bytes < observer.minimum_bytes {
            continue;
        }
        let mut counts = observer.counts.lock().unwrap();
        let selected = if final_audit {
            &mut counts.final_audits
        } else {
            &mut counts.decodes
        };
        *selected.entry(entry.log_id.index).or_default() += 1;
    }
}

/// Keep ordinary test output and optionally retain measurements from a quiet
/// complete shard. This changes diagnostics only, never test selection or bounds.
pub(crate) fn report(value: serde_json::Value) {
    eprintln!("scope_payload_write={value}");
    if let Some(path) = std::env::var_os("OPC_SCOPE_PAYLOAD_COST_LOG") {
        use std::io::Write;
        static OUTPUT: Mutex<()> = Mutex::new(());
        let _output = OUTPUT.lock().unwrap();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("scope payload measurement output");
        writeln!(file, "{value}").expect("retain scope payload measurement");
    }
}
