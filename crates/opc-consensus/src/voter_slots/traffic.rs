use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

use super::{AuthenticatedVoterEvidence, VoterReplacementError};
use crate::{ConsensusNodeId, DURABLE_OPENRAFT_PROFILE};

/// Full monotonic observation window required independently on every survivor.
pub const VOTER_RECENT_TRAFFIC_WINDOW: Duration =
    Duration::from_millis(2 * DURABLE_OPENRAFT_PROFILE.election_timeout_max_millis);

/// Bounded, process-local observation of authenticated incarnation-key traffic.
///
/// Restart starts a fresh full window. A proof's original verification timestamp
/// is retained, so replaying an already consumed fact cannot extend the window.
#[derive(Debug)]
pub struct VoterTrafficWindow {
    seen: Mutex<BTreeMap<ConsensusNodeId, Observation>>,
}
#[derive(Debug)]
struct Observation {
    started: Instant,
    last: Option<Instant>,
}
impl VoterTrafficWindow {
    /// Track only the exact known members/candidate of a bounded fixed configuration.
    pub fn new(members: BTreeSet<ConsensusNodeId>) -> Self {
        Self {
            seen: Mutex::new(
                members
                    .into_iter()
                    .map(|node| {
                        (
                            node,
                            Observation {
                                started: Instant::now(),
                                last: None,
                            },
                        )
                    })
                    .collect(),
            ),
        }
    }

    /// Retain the current bounded set; a newly observed incarnation starts a full cold window.
    pub fn retain_members(&self, members: BTreeSet<ConsensusNodeId>) {
        let Ok(mut seen) = self.seen.lock() else {
            return;
        };
        seen.retain(|node, _| members.contains(node));
        for node in members {
            seen.entry(node).or_insert_with(|| Observation {
                started: Instant::now(),
                last: None,
            });
        }
    }

    /// Record a key proof before later envelope, retirement or payload checks can refuse it.
    /// The store first checks that this proof's key matches the retained target binding.
    pub fn observe(&self, proof: &AuthenticatedVoterEvidence) {
        let Ok(mut seen) = self.seen.lock() else {
            return;
        };
        if let Some(observation) = seen.get_mut(&proof.binding().source.identity.node_id()) {
            observation.last = Some(
                observation
                    .last
                    .map_or(proof.verified_at, |old| old.max(proof.verified_at)),
            );
        }
    }

    /// Fresh local absence check immediately before closing an intent's pre-dispatch gate.
    pub fn check_absent(&self, node: ConsensusNodeId) -> Result<(), VoterReplacementError> {
        let now = Instant::now();
        let seen = self
            .seen
            .lock()
            .map_err(|_| VoterReplacementError::Unavailable)?;
        let observation = seen
            .get(&node)
            .ok_or(VoterReplacementError::UnauthorizedReplacement)?;
        if observation
            .last
            .is_some_and(|time| now.saturating_duration_since(time) < VOTER_RECENT_TRAFFIC_WINDOW)
        {
            return Err(VoterReplacementError::TargetStillLive);
        }
        if now.saturating_duration_since(observation.started) < VOTER_RECENT_TRAFFIC_WINDOW {
            return Err(VoterReplacementError::ObservationIncomplete);
        }
        Ok(())
    }
}
