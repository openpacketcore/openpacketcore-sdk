//! Observe the pinned engine's synchronous tick handler without changing it.

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
    tick: bool,
    references: usize,
}

#[derive(Default)]
struct Spans {
    next: u64,
    live: HashMap<u64, ObservedSpan>,
    entered: HashMap<ThreadId, Vec<u64>>,
}

/// Only these two synchronous engine spans are enabled. Exiting
/// `handle_tick_election` proves the core has evaluated its election timer;
/// the runtime's next sleep registration alone proves only that Tick was sent.
#[derive(Clone)]
pub struct ProcessedTicks {
    spans: Arc<Mutex<Spans>>,
    processed: watch::Sender<HashMap<u64, (Instant, usize)>>,
}

impl ProcessedTicks {
    /// The fixture uses Tokio's current-thread runtime. Keep this thread-local
    /// subscriber installed through construction and the controlled election.
    pub fn install() -> (Self, tracing::subscriber::DefaultGuard) {
        let observer = Self {
            spans: Arc::default(),
            processed: watch::channel(HashMap::new()).0,
        };
        let guard = tracing::subscriber::set_default(observer.clone());
        (observer, guard)
    }

    pub async fn wait(&self, node: u64, registered_at: Instant, sent_ticks: usize) {
        self.processed
            .subscribe()
            .wait_for(|ticks| {
                ticks
                    .get(&node)
                    .is_some_and(|(at, count)| *at >= registered_at && *count >= sent_ticks)
            })
            .await
            .expect("core processed its registered tick");
    }
}

#[derive(Default)]
struct NodeField(Option<u64>);

impl Visit for NodeField {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "id" {
            self.0 = Some(format!("{value:?}").parse().expect("engine node ID"));
        }
    }
}

impl Subscriber for ProcessedTicks {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "openraft::core::raft_core"
            && matches!(metadata.name(), "handle_notify" | "handle_tick_election")
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        let mut fields = NodeField::default();
        attributes.record(&mut fields);
        let mut spans = self.spans.lock().unwrap();
        let node = fields.0.unwrap_or_else(|| {
            let parent = spans.entered[&std::thread::current().id()]
                .last()
                .expect("tick inside node notification");
            spans.live[parent].node
        });
        spans.next += 1;
        let id = spans.next;
        spans.live.insert(
            id,
            ObservedSpan {
                node,
                tick: attributes.metadata().name() == "handle_tick_election",
                references: 1,
            },
        );
        Id::from_u64(id)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, _: &Event<'_>) {}

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
        if span.tick {
            self.processed.send_modify(|ticks| {
                let processed = ticks.entry(span.node).or_insert((Instant::now(), 0));
                processed.0 = Instant::now();
                processed.1 += 1;
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
