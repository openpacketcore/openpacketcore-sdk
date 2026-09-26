//! Passive fixture observations. No request body or authority is retained.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use opc_session_store::{
    SessionConsensusPeerError, SessionConsensusRpcFamily, SessionConsensusWireRequest,
    SessionConsensusWireResponse,
};

const FAMILIES: [&str; 11] = [
    "vote",
    "append_entries",
    "append_entries_roster",
    "install_snapshot",
    "forward_mutation",
    "forward_roster_mutation",
    "read_index",
    "read_probe",
    "topology_admission_barrier",
    "leadership_transfer",
    "other",
];
const OUTCOMES: [&str; 4] = [
    "response_ok",
    "response_rejected",
    "transport_error",
    "cancelled",
];
const BOUNDS_US: [u64; 9] = [
    10, 100, 1_000, 5_000, 10_000, 50_000, 100_000, 500_000, 1_000_000,
];

#[derive(Default)]
struct Completed {
    count: AtomicU64,
    duration_us: AtomicU64,
    buckets: [AtomicU64; BOUNDS_US.len() + 1],
}

#[derive(Default)]
struct Family {
    attempted: AtomicU64,
    current: AtomicU64,
    peak: AtomicU64,
    completed: [Completed; OUTCOMES.len()],
}

#[derive(Default)]
pub(crate) struct Observations {
    families: [Family; FAMILIES.len()],
}

impl Observations {
    pub(crate) fn begin(self: &Arc<Self>, request: &SessionConsensusWireRequest) -> Call {
        let index = match request.family {
            SessionConsensusRpcFamily::Vote => 0,
            SessionConsensusRpcFamily::AppendEntries => 1,
            SessionConsensusRpcFamily::AppendEntriesRoster => 2,
            SessionConsensusRpcFamily::InstallSnapshot => 3,
            SessionConsensusRpcFamily::ForwardMutation => 4,
            SessionConsensusRpcFamily::ForwardRosterMutation => 5,
            SessionConsensusRpcFamily::ReadBarrier if request.payload.is_empty() => 6,
            SessionConsensusRpcFamily::ReadBarrier => 7,
            SessionConsensusRpcFamily::TopologyAdmissionBarrier => 8,
            SessionConsensusRpcFamily::LeadershipTransfer => 9,
            _ => 10,
        };
        let family = &self.families[index];
        family.attempted.fetch_add(1, Ordering::Relaxed);
        let current = family.current.fetch_add(1, Ordering::Relaxed) + 1;
        family.peak.fetch_max(current, Ordering::Relaxed);
        Call {
            observations: Arc::clone(self),
            index,
            outcome: 3,
            started: Instant::now(),
        }
    }

    pub(crate) fn snapshot(&self) -> serde_json::Value {
        let families: Vec<_> = self
            .families
            .iter()
            .zip(FAMILIES)
            .map(|(family, label)| {
                let outcomes: Vec<_> = family
                    .completed
                    .iter()
                    .zip(OUTCOMES)
                    .map(|(completed, outcome)| {
                        serde_json::json!({
                            "outcome": outcome,
                            "count": completed.count.load(Ordering::Relaxed),
                            "duration_us": completed.duration_us.load(Ordering::Relaxed),
                            "buckets": completed.buckets.iter()
                                .map(|bucket| bucket.load(Ordering::Relaxed)).collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                serde_json::json!({
                    "family": label,
                    "attempted": family.attempted.load(Ordering::Relaxed),
                    "current": family.current.load(Ordering::Relaxed),
                    "lifetime_peak": family.peak.load(Ordering::Relaxed),
                    "outcomes": outcomes,
                })
            })
            .collect();
        serde_json::json!({"bounds_us": BOUNDS_US, "families": families})
    }
}

pub(crate) struct Call {
    observations: Arc<Observations>,
    index: usize,
    outcome: usize,
    started: Instant,
}

impl Call {
    pub(crate) fn finish(
        mut self,
        result: &Result<SessionConsensusWireResponse, SessionConsensusPeerError>,
    ) {
        self.outcome = match result {
            Ok(response) if response.result.is_ok() => 0,
            Ok(_) => 1,
            Err(_) => 2,
        };
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        let elapsed = u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let family = &self.observations.families[self.index];
        let completed = &family.completed[self.outcome];
        completed.count.fetch_add(1, Ordering::Relaxed);
        completed.duration_us.fetch_add(elapsed, Ordering::Relaxed);
        let bucket = BOUNDS_US.partition_point(|bound| *bound < elapsed);
        completed.buckets[bucket].fetch_add(1, Ordering::Relaxed);
        family.current.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InProcessConsensusPeer;
    use opc_consensus::{
        ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusConfigurationId,
    };
    use opc_session_store::{
        SessionConsensusIdentity, SessionConsensusNodeId, SessionConsensusPeer,
        SessionConsensusRpcHandler,
    };

    #[derive(Debug, Default)]
    struct HeldHandler {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl SessionConsensusRpcHandler for HeldHandler {
        async fn handle(
            &self,
            _: SessionConsensusNodeId,
            _: SessionConsensusWireRequest,
        ) -> SessionConsensusWireResponse {
            self.entered.notify_one();
            self.release.notified().await;
            SessionConsensusWireResponse {
                result: Ok(Vec::new()),
            }
        }
    }

    #[derive(Debug)]
    struct RejectedHandler;

    #[async_trait::async_trait]
    impl SessionConsensusRpcHandler for RejectedHandler {
        async fn handle(
            &self,
            _: SessionConsensusNodeId,
            _: SessionConsensusWireRequest,
        ) -> SessionConsensusWireResponse {
            SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::Rejected),
            }
        }
    }

    fn request() -> SessionConsensusWireRequest {
        SessionConsensusWireRequest::try_new(
            SessionConsensusIdentity::new(
                ConsensusClusterId::from_bytes([1; 32]),
                ConsensusConfigurationId::from_bytes([2; 32]),
                ConsensusConfigurationEpoch::new(1).unwrap(),
            ),
            SessionConsensusNodeId::new(1).unwrap(),
            SessionConsensusRpcFamily::ReadBarrier,
            Vec::new(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn actual_peer_call_accounts_rejection_completion_and_cancelled_overlap() {
        let peer = Arc::new(InProcessConsensusPeer::new(
            SessionConsensusNodeId::new(2).unwrap(),
        ));
        peer.set_online(false);
        assert!(peer.call(request()).await.is_err());
        peer.set_online(true);
        let handler = Arc::new(HeldHandler::default());
        peer.install(handler.clone()).await;
        let first = tokio::spawn({
            let peer = peer.clone();
            async move { peer.call(request()).await }
        });
        handler.entered.notified().await;
        let second = tokio::spawn({
            let peer = peer.clone();
            async move { peer.call(request()).await }
        });
        handler.entered.notified().await;
        let active = peer.rpc_observations.snapshot();
        assert_eq!(active["families"][6]["current"], 2);
        assert_eq!(active["families"][6]["lifetime_peak"], 2);
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        handler.release.notify_one();
        assert!(second.await.unwrap().unwrap().result.is_ok());
        peer.install(Arc::new(RejectedHandler)).await;
        assert!(peer.call(request()).await.unwrap().result.is_err());
        let mut probe = request();
        probe.payload.push(1);
        assert!(peer.call(probe).await.unwrap().result.is_err());
        let snapshot = peer.rpc_observations.snapshot();
        let row = &snapshot["families"][6];
        assert_eq!(row["family"], "read_index");
        assert_eq!(row["attempted"], 4);
        assert_eq!(row["current"], 0);
        assert_eq!(row["outcomes"][0]["count"], 1);
        assert_eq!(row["outcomes"][1]["count"], 1);
        assert_eq!(row["outcomes"][2]["count"], 1);
        assert_eq!(row["outcomes"][3]["count"], 1);
        for outcome in row["outcomes"].as_array().unwrap() {
            let buckets: u64 = outcome["buckets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|count| count.as_u64().unwrap())
                .sum();
            assert_eq!(buckets, outcome["count"].as_u64().unwrap());
        }
        assert_eq!(snapshot["families"][7]["family"], "read_probe");
        assert_eq!(snapshot["families"][7]["attempted"], 1);
        assert_eq!(snapshot["families"][7]["current"], 0);
        assert_eq!(snapshot["families"][7]["outcomes"][1]["count"], 1);
    }
}
