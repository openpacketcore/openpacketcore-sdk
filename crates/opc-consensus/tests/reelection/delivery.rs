//! Observe actual Tick delivery and core handling without changing the engine.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;

use tokio::sync::watch;
use tokio::time::Instant;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

struct ObservedSpan {
    node: u64,
    election: bool,
    references: usize,
}

#[derive(Default)]
struct Spans {
    next: u64,
    live: HashMap<u64, ObservedSpan>,
    entered: HashMap<ThreadId, Vec<u64>>,
}

#[derive(Clone, Copy, Default)]
struct Progress {
    sent: usize,
    sent_at: Option<Instant>,
    handled: usize,
    handled_at: Option<Instant>,
}

/// A leader also registers replication-worker sleeps. Observe the tick task's
/// real sequence number and completion of the synchronous core tick handler,
/// so those unrelated sleeps cannot satisfy the controlled-clock barrier.
#[derive(Clone)]
pub struct TickDelivery {
    spans: Arc<Mutex<Spans>>,
    progress: watch::Sender<HashMap<u64, Progress>>,
}

impl TickDelivery {
    /// Install before node construction on the fixture's current-thread runtime.
    pub fn install() -> (Self, tracing::subscriber::DefaultGuard) {
        let observer = Self {
            spans: Arc::default(),
            progress: watch::channel(HashMap::new()).0,
        };
        let guard = tracing::subscriber::set_default(observer.clone());
        (observer, guard)
    }

    pub async fn wait(&self, node: u64, at: Instant) {
        self.progress
            .subscribe()
            .wait_for(|nodes| {
                nodes.get(&node).is_some_and(|progress| {
                    progress.sent_at.is_some_and(|sent| sent >= at)
                        && progress.handled_at.is_some_and(|handled| handled >= at)
                        && progress.handled == progress.sent
                })
            })
            .await
            .expect("core handled every sent tick at the controlled clock");
    }
}

/// The engine's tick span inherits this node identity during construction.
pub fn node_span(node: u64) -> tracing::Span {
    tracing::debug_span!(target: "opc_consensus_test", "election_node", id = node)
}

#[derive(Default)]
struct Fields {
    node: Option<u64>,
    sent: Option<usize>,
}

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "id" {
            self.node = Some(format!("{value:?}").parse().expect("engine node ID"));
        } else if field.name() == "message" {
            if let Some(sequence) = format!("{value:?}").strip_prefix("Tick sent: ") {
                self.sent = Some(sequence.parse().expect("engine tick sequence"));
            }
        }
    }
}

impl Subscriber for TickDelivery {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        (metadata.target() == "opc_consensus_test" && metadata.name() == "election_node")
            || (metadata.target() == "openraft::core::tick"
                && (metadata.name() == "tick" || metadata.is_event()))
            || (metadata.target() == "openraft::core::raft_core"
                && matches!(metadata.name(), "handle_notify" | "handle_tick_election"))
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        let mut fields = Fields::default();
        attributes.record(&mut fields);
        let mut spans = self.spans.lock().unwrap();
        let node = fields.node.unwrap_or_else(|| {
            let parent = spans.entered[&std::thread::current().id()]
                .last()
                .expect("tick has a node construction or notification parent");
            spans.live[parent].node
        });
        spans.next += 1;
        let id = spans.next;
        spans.live.insert(
            id,
            ObservedSpan {
                node,
                election: attributes.metadata().name() == "handle_tick_election",
                references: 1,
            },
        );
        Id::from_u64(id)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let Some(sequence) = fields.sent else {
            return;
        };
        let node = {
            let spans = self.spans.lock().unwrap();
            let parent = spans.entered[&std::thread::current().id()]
                .last()
                .expect("tick sent inside its node's tick task");
            spans.live[parent].node
        };
        self.progress.send_modify(|nodes| {
            let progress = nodes.entry(node).or_default();
            assert_eq!(sequence, progress.sent + 1, "observe every real tick");
            progress.sent = sequence;
            progress.sent_at = Some(Instant::now());
        });
    }

    fn enter(&self, id: &Id) {
        self.spans
            .lock()
            .unwrap()
            .entered
            .entry(std::thread::current().id())
            .or_default()
            .push(id.into_u64());
    }

    fn exit(&self, id: &Id) {
        let mut spans = self.spans.lock().unwrap();
        let stack = spans.entered.get_mut(&std::thread::current().id()).unwrap();
        assert_eq!(stack.pop(), Some(id.into_u64()));
        let span = &spans.live[&id.into_u64()];
        if span.election {
            self.progress.send_modify(|nodes| {
                let progress = nodes.entry(span.node).or_default();
                progress.handled += 1;
                progress.handled_at = Some(Instant::now());
                assert!(progress.handled <= progress.sent);
            });
        }
    }

    fn clone_span(&self, id: &Id) -> Id {
        self.spans
            .lock()
            .unwrap()
            .live
            .get_mut(&id.into_u64())
            .unwrap()
            .references += 1;
        id.clone()
    }

    fn try_close(&self, id: Id) -> bool {
        let mut spans = self.spans.lock().unwrap();
        let span = spans.live.get_mut(&id.into_u64()).unwrap();
        span.references -= 1;
        if span.references == 0 {
            spans.live.remove(&id.into_u64());
            true
        } else {
            false
        }
    }
}
