//! Bounded value-free observations; no request, response or timing alteration.

use super::*;
use opc_consensus::engine::error::RaftError;
use opc_consensus::engine::raft::{VoteRequest, VoteResponse};
use serde::Deserialize;

const SAMPLES: usize = 32;

#[derive(Deserialize)]
struct Wire<T> {
    revision: u16,
    value: T,
}

type Reply = Result<VoteResponse<ConsensusNodeId>, RaftError<ConsensusNodeId>>;

pub(super) struct Pending {
    target: usize,
    phase: tokio::time::Instant,
    started: tokio::time::Instant,
    request: VoteRequest<ConsensusNodeId>,
    revision: u16,
}

#[derive(Clone, Copy, Debug, Default)]
struct Sample {
    target: usize,
    start_millis: u64,
    elapsed_millis: u64,
    transport_ok: bool,
    service_ok: bool,
    decoded: bool,
    revision_matches: bool,
    granted: bool,
    same_vote: bool,
    same_term: bool,
    committed_vote: bool,
    same_last_log: bool,
    greater_last_log: bool,
}

#[derive(Debug, Default)]
struct Phase {
    started: Option<tokio::time::Instant>,
    count: usize,
    skipped: usize,
    invalid: usize,
    samples: [Sample; SAMPLES],
}

#[derive(Debug, Default)]
pub(super) struct Observation(Mutex<Phase>);

impl Observation {
    pub(super) fn capture(&self, request: &ConsensusWireRequest, target: usize) -> Option<Pending> {
        if request.family != ConsensusRpcFamily::Vote {
            return None;
        }
        let phase = self
            .0
            .lock()
            .expect("bounded election observation")
            .started?;
        let started = tokio::time::Instant::now();
        let value: Wire<VoteRequest<ConsensusNodeId>> =
            match opc_consensus::decode_bounded(&request.payload) {
                Ok(value) => value,
                Err(_) => {
                    let mut state = self.0.lock().expect("bounded election observation");
                    state.invalid = state.invalid.saturating_add(1);
                    return None;
                }
            };
        Some(Pending {
            target,
            phase,
            started,
            request: value.value,
            revision: value.revision,
        })
    }

    pub(super) fn record(
        &self,
        pending: Pending,
        response: &Result<ConsensusWireResponse, ConsensusPeerError>,
    ) {
        let now = tokio::time::Instant::now();
        let mut sample = Sample {
            target: pending.target,
            start_millis: u64::try_from(pending.started.duration_since(pending.phase).as_millis())
                .unwrap_or(u64::MAX),
            elapsed_millis: u64::try_from(now.duration_since(pending.started).as_millis())
                .unwrap_or(u64::MAX),
            transport_ok: response.is_ok(),
            ..Sample::default()
        };
        if let Ok(response) = response {
            sample.service_ok = response.result.is_ok();
            if let Ok(payload) = &response.result {
                if let Ok(reply) = opc_consensus::decode_bounded::<Wire<Reply>>(payload) {
                    sample.revision_matches = reply.revision == pending.revision;
                    if let Ok(vote) = reply.value {
                        sample.decoded = true;
                        sample.granted = vote.vote_granted;
                        sample.same_vote = vote.vote == pending.request.vote;
                        sample.same_term =
                            vote.vote.leader_id.term == pending.request.vote.leader_id.term;
                        sample.committed_vote = vote.vote.committed;
                        sample.same_last_log = vote.last_log_id == pending.request.last_log_id;
                        sample.greater_last_log = vote.last_log_id > pending.request.last_log_id;
                    }
                }
            }
        }
        let mut state = self.0.lock().expect("bounded election observation");
        if state.count == SAMPLES {
            state.skipped = state.skipped.saturating_add(1);
            return;
        }
        let index = state.count;
        state.samples[index] = sample;
        state.count += 1;
    }
}

pub(super) fn begin(faults: &[Arc<Fault>; 3]) {
    let now = tokio::time::Instant::now();
    for fault in faults {
        let mut phase = fault
            .election
            .0
            .lock()
            .expect("begin bounded election observation");
        assert!(phase.started.is_none());
        phase.started = Some(now);
    }
}

pub(super) fn report(faults: &[Arc<Fault>; 3]) {
    for (source, fault) in faults.iter().enumerate() {
        let phase = fault
            .election
            .0
            .lock()
            .expect("read bounded election observations");
        if phase.started.is_none() {
            continue;
        }
        eprintln!(
            "CONFIG_CAPACITY_ELECTION_SUMMARY source={source} captured={} skipped={} invalid={}",
            phase.count, phase.skipped, phase.invalid
        );
        for sample in &phase.samples[..phase.count] {
            eprintln!("CONFIG_CAPACITY_ELECTION source={source} target={} start_ms={} elapsed_ms={} transport_ok={} service_ok={} decoded={} revision_matches={} granted={} same_vote={} same_term={} committed_vote={} same_last_log={} greater_last_log={}", sample.target, sample.start_millis, sample.elapsed_millis, sample.transport_ok, sample.service_ok, sample.decoded, sample.revision_matches, sample.granted, sample.same_vote, sample.same_term, sample.committed_vote, sample.same_last_log, sample.greater_last_log);
        }
    }
}
