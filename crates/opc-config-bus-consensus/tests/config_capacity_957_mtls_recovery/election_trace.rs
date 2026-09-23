//! Diagnostic observation of the exact pinned engine's existing election trace.
//!
//! This subscriber never prints event messages, vote identities or absolute
//! timestamps. It samples only the two existing timer callsites during the
//! original readiness future, including panic or timeout unwinding. Samples are
//! aggregate observations across the
//! surviving engines, not a per-member trace or a causal fix. The engine,
//! timing profile, deadline and existing test assertions remain unchanged.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

const TIMER_SAMPLE_LINE: u32 = 1471;
const TIMER_DEFERRED_LINE: u32 = 1481;
const MAX_SAMPLES: usize = 32;

#[derive(Clone, Copy)]
struct TimerSample {
    phase_nanos: u128,
    vote_age_nanos: u128,
    election_timeout_nanos: u128,
}

struct Phase {
    started: Instant,
    samples: [Option<TimerSample>; MAX_SAMPLES],
    sample_count: usize,
    deferred_count: usize,
    malformed_count: usize,
    overflow_count: usize,
}

#[derive(Clone)]
pub(super) struct ElectionTrace {
    phase: Arc<Mutex<Option<Phase>>>,
    next_span: Arc<AtomicU64>,
}

pub(super) struct PhaseReport<'a>(&'a ElectionTrace);

impl Drop for PhaseReport<'_> {
    fn drop(&mut self) {
        self.0.finish_and_report();
    }
}

impl ElectionTrace {
    pub(super) fn install() -> Self {
        let observer = Self {
            phase: Arc::new(Mutex::new(None)),
            next_span: Arc::new(AtomicU64::new(1)),
        };
        tracing::subscriber::set_global_default(observer.clone())
            .expect("install diagnostic subscriber in this test binary");
        observer
    }

    pub(super) fn begin_phase(&self) -> PhaseReport<'_> {
        let mut phase = self.phase.lock().expect("diagnostic phase lock");
        assert!(phase.is_none(), "one readiness observation phase");
        *phase = Some(Phase {
            started: Instant::now(),
            samples: [None; MAX_SAMPLES],
            sample_count: 0,
            deferred_count: 0,
            malformed_count: 0,
            overflow_count: 0,
        });
        PhaseReport(self)
    }

    fn finish_and_report(&self) {
        let phase = self.phase.lock().expect("diagnostic phase lock").take();
        let Some(phase) = phase else {
            eprintln!("CONFIG_CAPACITY_ELECTION_TRACE phase_started=false");
            return;
        };
        eprintln!(
            "CONFIG_CAPACITY_ELECTION_TRACE phase_started=true samples={} deferred={} malformed={} overflow={}",
            phase.sample_count, phase.deferred_count, phase.malformed_count, phase.overflow_count,
        );
        for (index, sample) in phase.samples.into_iter().flatten().enumerate() {
            eprintln!(
                "CONFIG_CAPACITY_ELECTION_SAMPLE sample={index} phase_ns={} vote_age_ns={} timeout_ns={}",
                sample.phase_nanos, sample.vote_age_nanos, sample.election_timeout_nanos,
            );
        }
    }
}

impl Subscriber for ElectionTrace {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        // These source lines are pinned by the workspace's immutable Openraft
        // revision. A changed dependency needs a fresh source review; absent
        // or malformed samples cannot be interpreted as timing evidence.
        metadata.is_event()
            && metadata.target() == "openraft::core::raft_core"
            && *metadata.level() == tracing::Level::DEBUG
            && matches!(
                metadata.line(),
                Some(TIMER_SAMPLE_LINE | TIMER_DEFERRED_LINE)
            )
    }

    fn new_span(&self, _attributes: &Attributes<'_>) -> Id {
        Id::from_u64(self.next_span.fetch_add(1, Ordering::Relaxed))
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut phase = self.phase.lock().expect("diagnostic phase lock");
        let Some(phase) = phase.as_mut() else {
            return;
        };
        if event.metadata().line() == Some(TIMER_DEFERRED_LINE) {
            phase.deferred_count += 1;
            return;
        }
        let phase_nanos = phase.started.elapsed().as_nanos();
        let mut message = TimerMessage::default();
        event.record(&mut message);
        let Some((vote_age_nanos, election_timeout_nanos)) = timer_values(&message.0) else {
            phase.malformed_count += 1;
            return;
        };
        let Some(slot) = phase.samples.get_mut(phase.sample_count) else {
            phase.overflow_count += 1;
            return;
        };
        *slot = Some(TimerSample {
            phase_nanos,
            vote_age_nanos,
            election_timeout_nanos,
        });
        phase.sample_count += 1;
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

#[derive(Default)]
struct TimerMessage(String);

impl Visit for TimerMessage {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        }
    }
}

fn timer_values(message: &str) -> Option<(u128, u128)> {
    let (_, durations) = message.split_once("now-utime:Some(")?;
    let (age, timeout) = durations.split_once("), election_timeout: ")?;
    Some((duration_nanos(age)?, duration_nanos(timeout)?))
}

fn duration_nanos(value: &str) -> Option<u128> {
    let (number, scale) = [
        ("ns", 1_u128),
        ("µs", 1_000),
        ("ms", 1_000_000),
        ("s", 1_000_000_000),
    ]
    .into_iter()
    .find_map(|(unit, scale)| value.strip_suffix(unit).map(|number| (number, scale)))?;
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    let whole = whole.parse::<u128>().ok()?.checked_mul(scale)?;
    if fraction.is_empty() {
        return Some(whole);
    }
    let divisor = 10_u128.checked_pow(fraction.len().try_into().ok()?)?;
    let fraction = fraction.parse::<u128>().ok()?.checked_mul(scale)?;
    if !fraction.is_multiple_of(divisor) {
        return None;
    }
    whole.checked_add(fraction / divisor)
}

#[test]
fn pinned_engine_durations_parse_without_rounding_or_absent_value_substitution() {
    for (input, expected) in [
        ("0ns", 0),
        ("7ns", 7),
        ("1.234µs", 1_234),
        ("24.381772ms", 24_381_772),
        ("15.318s", 15_318_000_000),
    ] {
        assert_eq!(duration_nanos(input), Some(expected));
    }
    assert_eq!(
        timer_values("discarded prefix, now-utime:Some(24.381772ms), election_timeout: 15.318s"),
        Some((24_381_772, 15_318_000_000)),
    );
    for input in ["NaNs", "-1s", "1.1ns", "1e3s", "1sec", ""] {
        assert_eq!(duration_nanos(input), None);
    }
    assert_eq!(timer_values("now-utime:None, election_timeout: 13s"), None);
}
