//! Host-portable RED scale evidence for #720 (Option B).
//!
//! These tests characterize the current bounded traffic-proof limits at the
//! required ePDG pool scale (50,000 identities, 10,000 simultaneous attempts,
//! 40,000-event burst). They intentionally do **not** implement scaling and do
//! not change any production path, map, pin, object, ABI or proof semantic:
//! they are the preserved RED evidence the issue asks for before the pinned-ABI
//! (Option A) work.
//!
//! No live packet proof is claimed here. Every assertion is arithmetic or a
//! bounded in-memory model; the release-mode benchmark is `#[ignore]`d and must
//! be run in CI, never as a proof claim.

use opc_gtpu_ebpf_common::{
    GTPU_TRAFFIC_OBSERVATION_EVENT_LEN, GTPU_TRAFFIC_OBSERVATION_RING_BYTES,
};

use super::super::{
    traffic_attempt_capacity_available, traffic_observation_batch_full, MAX_TRAFFIC_PROOF_ATTEMPTS,
    MAX_TRAFFIC_PROOF_DRAIN_BATCH, TRAFFIC_OBSERVATION_SEQUENCE_WINDOW,
};

/// Required attached identities per pool (#720).
const REQUIRED_IDENTITIES: usize = 50_000;
/// Required simultaneous live proof attempts per pool (#720).
const REQUIRED_ATTEMPTS: usize = 10_000;
/// Required burst event count (#720).
const REQUIRED_BURST_EVENTS: usize = 40_000;
/// Events that fit in the current pinned ring, at 96 bytes each.
const CURRENT_RING_RECORDS: usize =
    (GTPU_TRAFFIC_OBSERVATION_RING_BYTES as usize) / GTPU_TRAFFIC_OBSERVATION_EVENT_LEN;

/// Full-scan work model: one scan of the shared event set per attempt.
const fn full_scan_work(events: usize, attempts: usize) -> usize {
    events.saturating_mul(attempts)
}

/// Group-indexed work model: one pass over events plus one delivery per event.
const fn group_indexed_work(events: usize) -> usize {
    events
}

/// Assert compiled/characterized evidence without tripping
/// `clippy::assertions_on_constants` for intentional constant bounds.
fn assert_evidence(condition: bool, evidence: &str) {
    assert!(condition, "{evidence}");
}

#[test]
fn current_limits_are_below_required_pool_scale() {
    assert_eq!(GTPU_TRAFFIC_OBSERVATION_EVENT_LEN, 96);
    assert_eq!(GTPU_TRAFFIC_OBSERVATION_RING_BYTES, 65_536);
    assert_eq!(CURRENT_RING_RECORDS, 682);
    assert_eq!(MAX_TRAFFIC_PROOF_ATTEMPTS, 256);
    assert_eq!(MAX_TRAFFIC_PROOF_DRAIN_BATCH, 4096);
    assert_eq!(TRAFFIC_OBSERVATION_SEQUENCE_WINDOW, 4096);

    assert_evidence(
        CURRENT_RING_RECORDS < REQUIRED_BURST_EVENTS,
        "current ring records are below the required burst",
    );
    assert_evidence(
        MAX_TRAFFIC_PROOF_ATTEMPTS < REQUIRED_ATTEMPTS,
        "current attempt cap is below the required simultaneous attempts",
    );
    assert_evidence(
        MAX_TRAFFIC_PROOF_DRAIN_BATCH < REQUIRED_BURST_EVENTS,
        "current drain batch cannot carry the required burst in one bounded pass",
    );
    assert_evidence(
        (TRAFFIC_OBSERVATION_SEQUENCE_WINDOW as usize) < REQUIRED_BURST_EVENTS,
        "the current replay window is smaller than the required burst",
    );
    assert_evidence(
        MAX_TRAFFIC_PROOF_ATTEMPTS < REQUIRED_IDENTITIES,
        "the current attempt cap is far below the required retained identities",
    );
}

#[test]
fn attempt_capacity_predicate_fails_closed_at_the_exact_boundary() {
    assert!(traffic_attempt_capacity_available(0));
    assert!(traffic_attempt_capacity_available(
        MAX_TRAFFIC_PROOF_ATTEMPTS - 1
    ));
    assert!(!traffic_attempt_capacity_available(
        MAX_TRAFFIC_PROOF_ATTEMPTS
    ));
    assert!(!traffic_attempt_capacity_available(REQUIRED_ATTEMPTS));
    // The exact predicate used by the production admission/renewal paths.
    assert_evidence(
        MAX_TRAFFIC_PROOF_ATTEMPTS < REQUIRED_ATTEMPTS,
        "the predicate boundary is below the required simultaneous attempts",
    );
}

#[test]
fn observation_drain_marks_the_exact_batch_boundary_overflowed() {
    assert!(!traffic_observation_batch_full(
        0,
        MAX_TRAFFIC_PROOF_DRAIN_BATCH
    ));
    assert!(!traffic_observation_batch_full(
        MAX_TRAFFIC_PROOF_DRAIN_BATCH - 1,
        MAX_TRAFFIC_PROOF_DRAIN_BATCH
    ));
    assert!(traffic_observation_batch_full(
        MAX_TRAFFIC_PROOF_DRAIN_BATCH,
        MAX_TRAFFIC_PROOF_DRAIN_BATCH
    ));
    assert!(traffic_observation_batch_full(
        REQUIRED_BURST_EVENTS,
        MAX_TRAFFIC_PROOF_DRAIN_BATCH
    ));
    // The whole current ring fits inside one current drain budget; the
    // required burst does not.
    assert_evidence(
        CURRENT_RING_RECORDS < MAX_TRAFFIC_PROOF_DRAIN_BATCH,
        "the current ring fits inside one current drain budget",
    );
    assert_evidence(
        REQUIRED_BURST_EVENTS > MAX_TRAFFIC_PROOF_DRAIN_BATCH,
        "the required burst does not fit one current drain budget",
    );
}

#[test]
fn full_scan_work_dominates_group_indexed_work_at_required_scale() {
    let baseline_full_scan = full_scan_work(CURRENT_RING_RECORDS, MAX_TRAFFIC_PROOF_ATTEMPTS);
    let baseline_indexed = group_indexed_work(CURRENT_RING_RECORDS);
    let required_full_scan = full_scan_work(REQUIRED_BURST_EVENTS, REQUIRED_ATTEMPTS);
    let required_indexed = group_indexed_work(REQUIRED_BURST_EVENTS);

    assert_eq!(baseline_full_scan, 682 * 256);
    assert_eq!(required_full_scan, 400_000_000);
    assert_eq!(required_indexed, 40_000);
    assert!(baseline_indexed < baseline_full_scan);
    assert!(
        required_full_scan > required_indexed.saturating_mul(1_000),
        "shared-event full scan does {required_full_scan} model operations against {required_indexed} for a group-indexed pass"
    );
    assert!(
        required_full_scan > baseline_full_scan.saturating_mul(1_000),
        "the required pool widens the full-scan gap by more than three orders of magnitude"
    );
}

#[test]
fn baseline_scan_and_grouped_index_agree_below_capacity() {
    // Bounded baseline model: one shared event set, every attempt scans it.
    let events = CURRENT_RING_RECORDS;
    let attempts = MAX_TRAFFIC_PROOF_ATTEMPTS;
    let groups: Vec<usize> = (0..events).map(|event| event % attempts).collect();
    let mut full_scan_matches = 0_usize;
    for group in &groups {
        for attempt in 0..attempts {
            if *group == attempt {
                full_scan_matches += 1;
            }
        }
    }
    // Group-indexed model: one event pass, one indexed delivery each.
    let mut index = std::collections::BTreeMap::<usize, usize>::new();
    for group in &groups {
        *index.entry(*group).or_default() += 1;
    }
    let indexed_matches: usize = index.values().sum();
    assert_eq!(full_scan_matches, events);
    assert_eq!(indexed_matches, events);
    assert_eq!(full_scan_matches, indexed_matches);
}

/// Release-mode benchmark evidence for the required pool size.
///
/// This is intentionally `#[ignore]`d: it is a CI/qualification artifact, not a
/// normal test. It uses one shared event set and one shared attempt set to
/// contrast the current full-scan model with a group-indexed model; it never
/// claims live packet proof or accesses a map/ring.
///
/// Run with:
/// `cargo test -p opc-gtpu-dataplane --release --lib scale_evidence -- --ignored --nocapture`
#[test]
#[ignore = "release-mode scale benchmark evidence; run in CI with --release --ignored"]
fn scale_benchmark_evidence_for_required_pool_is_bounded() {
    if cfg!(debug_assertions) {
        eprintln!("scale benchmark evidence skipped in debug; use --release");
        return;
    }
    let started = std::time::Instant::now();

    // Bounded inputs: 40,000 events and 10,000 attempts, all in-memory.
    let events: Vec<usize> = (0..REQUIRED_BURST_EVENTS)
        .map(|event| event % REQUIRED_ATTEMPTS)
        .collect();
    let attempts: Vec<usize> = (0..REQUIRED_ATTEMPTS).collect();
    let events_len = events.len();
    let attempts_len = attempts.len();

    // Current model: every attempt scans the shared event set.
    let full_scan_started = std::time::Instant::now();
    let mut full_scan_matches = 0_usize;
    for attempt in &attempts {
        for event_group in &events {
            if event_group == attempt {
                full_scan_matches += 1;
            }
        }
    }
    let full_scan_elapsed = full_scan_started.elapsed();

    // Group-indexed model: one pass over events into a bounded index.
    let indexed_started = std::time::Instant::now();
    let mut index = std::collections::BTreeMap::<usize, usize>::new();
    for group in &events {
        *index.entry(*group).or_default() += 1;
    }
    let indexed_matches: usize = index.values().sum();
    let indexed_elapsed = indexed_started.elapsed();

    assert_eq!(full_scan_matches, events_len);
    assert_eq!(indexed_matches, events_len);
    assert_eq!(full_scan_matches, indexed_matches);
    assert_eq!(attempts_len, REQUIRED_ATTEMPTS);
    // Bounded memory: events + attempts + one counter per observed group.
    assert!(index.len() <= REQUIRED_ATTEMPTS);
    let bounded_footprint = events_len
        .saturating_mul(core::mem::size_of::<usize>())
        .saturating_add(attempts_len.saturating_mul(core::mem::size_of::<usize>()))
        .saturating_add(
            index
                .len()
                .saturating_mul(core::mem::size_of::<(usize, usize)>()),
        );
    assert!(bounded_footprint < 4 * 1024 * 1024);

    // Diagnostics are counts only: no subscriber, group, device, address,
    // TEID, selector or other identity-bearing label is emitted.
    eprintln!(
        "scale_evidence events={events_len} attempts={attempts_len} indexed_groups={} full_scan_ops={} indexed_ops={} full_scan_ms={} indexed_ms={} bounded_footprint_bytes={bounded_footprint} live_proof_claimed=false",
        index.len(),
        full_scan_work(events_len, attempts_len),
        group_indexed_work(events_len),
        full_scan_elapsed.as_micros() as f64 / 1000.0,
        indexed_elapsed.as_micros() as f64 / 1000.0,
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(120));
}
