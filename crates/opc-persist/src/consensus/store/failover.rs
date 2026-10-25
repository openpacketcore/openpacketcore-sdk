//! Bounded failover acceleration for an unplanned configuration-leader loss.
//!
//! The pinned engine treats a committed follower vote as a leader lease of
//! `election_timeout_max` and only campaigns after that lease **and then** a
//! sampled election timeout. An unplanned leader loss therefore leaves survivors
//! quiet for the declared lease plus another full election window (13-16 s with
//! the fixed profile), well beyond the 10 s complete-operation budget (#1037).
//!
//! This module closes that avoidable second window without changing any
//! election, heartbeat, lease or quorum budget and without fabricating votes:
//! once a follower has observed no authenticated leader AppendEntries for one
//! complete declared lease plus the existing stale-route grace, it asks the
//! pinned engine for an **ordinary Pre-Vote round** through the public
//! `Trigger::elect()` API. The engine still gates the inquiry on every peer's
//! live leader lease, still persists a real self-vote, and still needs real
//! quorum vote grants; a healthy or merely delayed leader therefore cannot be
//! deposed. Requests from survivors are staggered deterministically by
//! membership rank so a whole survivor set does not campaign at once.
//!
//! The detection path is observable through [`ConfigFailoverStatus`] (typed,
//! value-free) and two counters.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use opc_consensus::engine::ServerState;
use opc_consensus::{
    DURABLE_CONSENSUS_FAILOVER_PATIENCE, DURABLE_CONSENSUS_FAILOVER_POLL_INTERVAL,
    DURABLE_CONSENSUS_FAILOVER_TRIGGER_STAGGER,
};
use serde::Serialize;

use super::*;

/// Upper bound on the declared configuration membership for the derived
/// detection bound.
const FAILOVER_MAX_MEMBERS: usize = crate::consensus::CONFIG_CONSENSUS_MAX_MEMBERS;

/// Conditional bound on the last-leader-contact to new-campaign request delay.
///
/// It is one complete declared leader-lease budget plus the existing
/// stale-route grace (the slowest legitimate survivor's leader contact),
/// the observation poll, and the deterministic stagger for the maximum
/// declared configuration membership. No election, heartbeat, lease or quorum
/// budget is increased; the bound is derived from the existing fixed profile.
pub const CONFIG_CONSENSUS_UNPLANNED_FAILOVER_DETECTION_BOUND: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_FAILOVER_PATIENCE.as_millis() as u64
        + DURABLE_CONSENSUS_FAILOVER_POLL_INTERVAL.as_millis() as u64
        + DURABLE_CONSENSUS_FAILOVER_TRIGGER_STAGGER.as_millis() as u64
            * (FAILOVER_MAX_MEMBERS as u64 - 2),
);

/// Typed, value-free failover observation for one configuration store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigFailoverState {
    /// This node is the engine leader; the accelerator never requests a campaign.
    Leading,
    /// No current leader is known to the local engine.
    NoKnownLeader,
    /// A leader is known and has been heard within the declared patience.
    Following,
    /// A leader is known but no authenticated leader contact was observed for at
    /// least the acceleration patience for this follower's rank.
    LeaderSilent {
        /// Milliseconds since the last authenticated leader contact.
        millis_since_leader_contact: u64,
        /// Whether this silence episode already requested one ordinary Pre-Vote
        /// campaign. The engine owns every retry and vote after that request.
        campaign_requested: bool,
    },
}

/// Redaction-safe failover evidence for readiness and telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ConfigFailoverStatus {
    /// Current failover observation.
    pub state: ConfigFailoverState,
    /// Total ordinary Pre-Vote campaigns requested by this store's accelerator.
    pub accelerated_campaigns: u64,
    /// Derived conditional bound on the last-contact to campaign-request delay.
    pub detection_bound_millis: u64,
}

#[derive(Default)]
pub(crate) struct ConfigFailoverAccelerator {
    contact: std::sync::Mutex<Option<LeaderContact>>,
    accelerated_campaigns: AtomicU64,
    trigger_failures: AtomicU64,
}

pub(super) struct LeaderContact {
    pub(super) leader: ConsensusNodeId,
    pub(super) term: u64,
    pub(super) at: tokio::time::Instant,
    /// One request per silence episode; a fresh leader contact re-arms it.
    pub(super) requested: bool,
}

/// Deterministic last-contact to campaign-request threshold for one follower
/// rank among the declared membership (the leader excluded).
///
/// Rank 0 waits only the declared patience (8.2 s); each later rank adds one
/// 50 ms stagger, so the highest possible rank 7 (maximum membership 9) waits
/// 8.55 s and the exported bound including the 500 ms poll is 9.05 s.
pub(super) fn failover_threshold_for_rank(rank: u64) -> Duration {
    DURABLE_CONSENSUS_FAILOVER_PATIENCE.saturating_add(
        DURABLE_CONSENSUS_FAILOVER_TRIGGER_STAGGER
            .saturating_mul(u32::try_from(rank).unwrap_or(u32::MAX)),
    )
}

impl ConfigFailoverAccelerator {
    pub(super) fn contact_locked(&self) -> std::sync::MutexGuard<'_, Option<LeaderContact>> {
        self.contact
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl ConsensusConfigStore {
    /// Record one authenticated leader contact observed by the transport.
    ///
    /// Only a sender that the local engine currently names as leader refreshes
    /// the silence clock, so a stale or rejected leader frame cannot postpone
    /// acceleration.
    pub(crate) fn record_leader_contact(&self, sender: ConsensusNodeId) {
        let (state, current_leader, current_term) =
            map_watch_snapshot(&self.inner.raft.metrics(), |metrics| {
                (metrics.state, metrics.current_leader, metrics.current_term)
            });
        if state == ServerState::Leader || current_leader != Some(sender) {
            return;
        }
        let now = tokio::time::Instant::now();
        let mut contact = self.inner.failover.contact_locked();
        match contact.as_mut() {
            Some(existing) if existing.leader == sender && existing.term == current_term => {
                existing.at = now;
                existing.requested = false;
            }
            _ => {
                *contact = Some(LeaderContact {
                    leader: sender,
                    term: current_term,
                    at: now,
                    requested: false,
                });
            }
        }
    }

    /// Typed, value-free failover observation for readiness and telemetry.
    pub fn failover_status(&self) -> ConfigFailoverStatus {
        let (state, current_leader, current_term) =
            map_watch_snapshot(&self.inner.raft.metrics(), |metrics| {
                (metrics.state, metrics.current_leader, metrics.current_term)
            });
        let accelerated_campaigns = self
            .inner
            .failover
            .accelerated_campaigns
            .load(Ordering::Acquire);
        let detection_bound_millis =
            u64::try_from(CONFIG_CONSENSUS_UNPLANNED_FAILOVER_DETECTION_BOUND.as_millis())
                .unwrap_or(u64::MAX);
        let state = match (state, current_leader) {
            (ServerState::Leader, _) => ConfigFailoverState::Leading,
            (_, None) => ConfigFailoverState::NoKnownLeader,
            (ServerState::Candidate, Some(_)) => ConfigFailoverState::NoKnownLeader,
            (_, Some(leader)) => {
                let contact = self.inner.failover.contact_locked();
                match contact
                    .as_ref()
                    .filter(|contact| contact.leader == leader && contact.term == current_term)
                {
                    Some(contact) => {
                        let silence = contact.at.elapsed();
                        let threshold = self.acceleration_threshold(leader);
                        if silence >= threshold {
                            ConfigFailoverState::LeaderSilent {
                                millis_since_leader_contact: u64::try_from(silence.as_millis())
                                    .unwrap_or(u64::MAX),
                                campaign_requested: contact.requested,
                            }
                        } else {
                            ConfigFailoverState::Following
                        }
                    }
                    None => ConfigFailoverState::Following,
                }
            }
        };
        ConfigFailoverStatus {
            state,
            accelerated_campaigns,
            detection_bound_millis,
        }
    }

    /// Deterministic rank of this node among configured followers, excluding the
    /// departed leader. Used only to stagger ordinary Pre-Vote requests.
    fn acceleration_rank(&self, leader: ConsensusNodeId) -> u64 {
        self.inner
            .members
            .iter()
            .filter(|member| **member != leader)
            .position(|member| *member == self.inner.local_node_id)
            .map(|rank| u64::try_from(rank).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }

    fn acceleration_threshold(&self, leader: ConsensusNodeId) -> Duration {
        failover_threshold_for_rank(self.acceleration_rank(leader))
    }

    fn failover_acceleration_eligible(&self) -> bool {
        !self.inner.shutdown.is_started()
            && !self.inner.repair_pending.load(Ordering::Acquire)
            && self.inner.voter_profile.is_none()
            && self
                .inner
                .automatic_elections_enabled
                .load(Ordering::Acquire)
    }

    /// Clear the one-per-episode reservation when the request was not issued.
    /// Only the exact leader/term reservation is cleared, so a heartbeat that
    /// already re-armed the contact is never disturbed.
    fn clear_failover_request_reservation(&self, leader: ConsensusNodeId, current_term: u64) {
        let mut contact = self.inner.failover.contact_locked();
        if let Some(existing) = contact.as_mut() {
            if existing.leader == leader && existing.term == current_term {
                existing.requested = false;
            }
        }
    }

    /// Count one issued ordinary Pre-Vote request. The last-contact timestamp is
    /// deliberately not touched: `LeaderSilent` must keep reporting the true
    /// silence interval after a campaign, and a fresh heartbeat is the only
    /// event that re-arms the episode clock.
    fn record_accelerated_campaign(&self, leader: ConsensusNodeId, current_term: u64) {
        self.inner
            .failover
            .accelerated_campaigns
            .fetch_add(1, Ordering::AcqRel);
        opc_redaction::metrics::METRICS
            .persist_failover_accelerated
            .fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            leader = %leader,
            term = current_term,
            "requested an early ordinary Pre-Vote campaign after declared leader silence"
        );
    }

    fn record_failover_trigger_failure(&self) {
        self.inner
            .failover
            .trigger_failures
            .fetch_add(1, Ordering::AcqRel);
        opc_redaction::metrics::METRICS
            .persist_failover_trigger_failures
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// Observe authenticated leader contact and request one bounded ordinary
/// campaign after the declared leader lease plus stale-route grace.
pub(crate) fn start_failover_watchdog(store: &ConsensusConfigStore) {
    let weak = Arc::downgrade(&store.inner);
    let mut metrics = store.inner.raft.metrics();
    tokio::spawn(async move {
        loop {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            let snapshot = {
                let current = metrics.borrow();
                if current.running_state.is_err() {
                    return;
                }
                (current.state, current.current_leader, current.current_term)
            };
            let store = ConsensusConfigStore { inner };
            if store.failover_acceleration_eligible() {
                if let (ServerState::Follower, Some(leader), term) = snapshot {
                    let threshold = store.acceleration_threshold(leader);
                    // Silence and the one-per-episode latch are read (and the
                    // latch is reserved) under one lock scope. A heartbeat that
                    // lands after this scope resets both together, so a late
                    // contact can never produce a second request for the same
                    // silence episode.
                    let request = {
                        let mut contact = store.inner.failover.contact_locked();
                        match contact.as_mut() {
                            Some(existing)
                                if existing.leader == leader && existing.term == term =>
                            {
                                let silence = existing.at.elapsed();
                                if silence >= threshold && !existing.requested {
                                    existing.requested = true;
                                    Some(silence)
                                } else {
                                    None
                                }
                            }
                            _ => {
                                *contact = Some(LeaderContact {
                                    leader,
                                    term,
                                    at: tokio::time::Instant::now(),
                                    requested: false,
                                });
                                None
                            }
                        }
                    };
                    if let Some(silence) = request {
                        // Verified against the pinned fork rev 2e1fb745:
                        // `openraft/src/raft/trigger.rs` documents that
                        // `Trigger::elect()` is *not* affected by
                        // `Raft::enable_elect(false)`, and the
                        // `ExternalCommand::Elect` handler in
                        // `openraft/src/core/raft_core.rs` runs the Pre-Vote
                        // path regardless. Re-check the SDK's mirrored flag
                        // immediately before issuing the request so a
                        // stale-true mirror cannot inflate the latch/metrics.
                        if !store
                            .inner
                            .automatic_elections_enabled
                            .load(Ordering::Acquire)
                        {
                            store.clear_failover_request_reservation(leader, term);
                        } else {
                            let trigger = tokio::time::timeout(
                                DURABLE_CONSENSUS_FAILOVER_POLL_INTERVAL,
                                store.inner.raft.trigger().elect(),
                            )
                            .await;
                            match trigger {
                                Ok(Ok(())) => {
                                    store.record_accelerated_campaign(leader, term);
                                    tracing::debug!(
                                        silence_millis =
                                            u64::try_from(silence.as_millis()).unwrap_or(u64::MAX),
                                        "reserved one bounded failover campaign request"
                                    );
                                }
                                Ok(Err(_)) => {
                                    store.clear_failover_request_reservation(leader, term);
                                    store.record_failover_trigger_failure();
                                }
                                // Keep the reservation: the core may still
                                // process the request after the observation
                                // timeout, and a retry would risk a duplicate.
                                Err(_) => {}
                            }
                        }
                    }
                } else if snapshot.0 != ServerState::Follower {
                    *store.inner.failover.contact_locked() = None;
                }
            }
            drop(store);
            tokio::select! {
                changed = metrics.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                _ = tokio::time::sleep(DURABLE_CONSENSUS_FAILOVER_POLL_INTERVAL) => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_consensus::{
        DURABLE_CONSENSUS_LEADER_QUORUM_LEASE, DURABLE_CONSENSUS_OPERATION_TIMEOUT,
        DURABLE_CONSENSUS_TIMING_PROFILE,
    };

    #[test]
    fn failover_threshold_staggers_only_the_observed_rank() {
        assert_eq!(failover_threshold_for_rank(0), Duration::from_millis(8_200));
        for rank in 3..=7 {
            assert_eq!(
                failover_threshold_for_rank(rank),
                Duration::from_millis(8_200 + rank * 50),
                "rank {rank} carries exactly one 50 ms stagger per earlier follower"
            );
        }
        assert_eq!(
            failover_threshold_for_rank(7)
                + opc_consensus::DURABLE_CONSENSUS_FAILOVER_POLL_INTERVAL,
            CONFIG_CONSENSUS_UNPLANNED_FAILOVER_DETECTION_BOUND,
            "the exported bound is the highest-rank threshold plus one poll"
        );
        assert!(failover_threshold_for_rank(u64::MAX) >= failover_threshold_for_rank(7));
    }

    #[test]
    fn failover_bound_is_derived_from_the_declared_profile() {
        assert_eq!(
            DURABLE_CONSENSUS_FAILOVER_PATIENCE,
            DURABLE_CONSENSUS_LEADER_QUORUM_LEASE + DURABLE_CONSENSUS_STALE_LEADER_ROUTE_GRACE
        );
        assert_eq!(
            DURABLE_CONSENSUS_FAILOVER_POLL_INTERVAL,
            Duration::from_millis(
                DURABLE_CONSENSUS_TIMING_PROFILE.append_entries_timeout_millis / 4
            )
        );
        assert_eq!(
            DURABLE_CONSENSUS_FAILOVER_TRIGGER_STAGGER,
            Duration::from_millis(50)
        );
        assert_eq!(
            CONFIG_CONSENSUS_UNPLANNED_FAILOVER_DETECTION_BOUND,
            Duration::from_millis(9_050)
        );
        assert!(
            CONFIG_CONSENSUS_UNPLANNED_FAILOVER_DETECTION_BOUND
                > DURABLE_CONSENSUS_FAILOVER_PATIENCE
        );
        assert!(
            CONFIG_CONSENSUS_UNPLANNED_FAILOVER_DETECTION_BOUND
                < DURABLE_CONSENSUS_OPERATION_TIMEOUT,
            "the derived first-campaign bound must stay inside the complete operation deadline"
        );
    }
}
