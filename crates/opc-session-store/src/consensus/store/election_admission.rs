//! Admission of timer-driven Openraft elections on this voter.
//!
//! Two independent owners decide whether this voter may start an election
//! when its election timer fires. The persistence protocol may suspend
//! elections, for example during Async recovery. The transport may report
//! that the local credentials admit no authenticated connection to a quorum,
//! for example when the local certificate has entered its rotation drain
//! window or has expired.
//!
//! A voter in that second state cannot win an election: its vote requests
//! can reach no peer. Each campaign would still persist a higher term. When
//! the voter later rejoins with fresh credentials, that inflated term would
//! reach the healthy leader in a response and force it to step down, costing
//! the cluster a leaderless election interval (#1005). Suspending its timer
//! elections instead lets it rejoin at the current term as an ordinary
//! follower. Explicitly triggered elections are unaffected.
//!
//! When the credentials admit connections again, the voter's election timer
//! has long expired. Re-enabling elections at once would make it campaign
//! before the leader's next heartbeat can reach it, and depose the leader
//! just the same. Timer elections therefore resume only after credentials
//! have stayed admitted for one full maximum election timeout, which gives
//! the leader's heartbeats, sent every heartbeat interval, time to arrive.

use super::*;

/// Credential admission is sampled far more often than the shortest Openraft
/// election timeout, so a voter stops campaigning before its first election
/// timer can fire after its credentials stop admitting connections.
const ELECTION_CREDENTIAL_POLL: Duration = Duration::from_millis(100);

/// Hold-down after credentials admit connections again, before this voter's
/// timer elections resume.
const ELECTION_CREDENTIAL_REJOIN_HOLD: Duration = Duration::from_millis(
    opc_consensus::DURABLE_CONSENSUS_TIMING_PROFILE.election_timeout_max_millis,
);

#[derive(Clone, Copy)]
struct ElectionAdmissionState {
    engine: bool,
    credentials: bool,
}

/// The conjunction of the engine-owned and credential-owned election
/// admissions, applied to Openraft's runtime election switch.
pub(super) struct ElectionAdmission {
    state: std::sync::Mutex<ElectionAdmissionState>,
}

impl ElectionAdmission {
    pub(super) fn new(engine: bool) -> Self {
        Self {
            state: std::sync::Mutex::new(ElectionAdmissionState {
                engine,
                credentials: true,
            }),
        }
    }

    /// Set the engine-owned admission and apply the combined switch.
    pub(super) fn set_engine(&self, raft: &SessionRaft, allowed: bool) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.engine = allowed;
        raft.runtime_config()
            .elect(state.engine && state.credentials);
    }

    /// Record the credential-owned admission. The combined switch is applied
    /// only when this admission changes.
    fn observe_credentials(&self, raft: &SessionRaft, admitted: bool) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.credentials == admitted {
            return;
        }
        state.credentials = admitted;
        raft.runtime_config()
            .elect(state.engine && state.credentials);
    }

    /// Follow the credential admission for as long as the store exists.
    pub(super) fn start_monitor(store: Weak<ConsensusSessionStoreInner>) {
        tokio::spawn(run_election_credential_monitor(store));
    }
}

async fn run_election_credential_monitor(store: Weak<ConsensusSessionStoreInner>) {
    let mut ticks = tokio::time::interval(ELECTION_CREDENTIAL_POLL);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Elections start admitted, as configured. After a suspension, this
    // records when the credentials first admitted connections again.
    let mut suspended = false;
    let mut admitted_since: Option<tokio::time::Instant> = None;
    loop {
        ticks.tick().await;
        let Some(store) = store.upgrade() else {
            return;
        };
        let Some(admitted) = local_credentials_admit_election(&store) else {
            continue;
        };
        let now = tokio::time::Instant::now();
        if !admitted {
            admitted_since = None;
            if !suspended {
                suspended = true;
                store
                    .election_admission
                    .observe_credentials(&store.raft, false);
            }
            continue;
        }
        if !suspended {
            continue;
        }
        let since = *admitted_since.get_or_insert(now);
        if now.saturating_duration_since(since) >= ELECTION_CREDENTIAL_REJOIN_HOLD {
            suspended = false;
            admitted_since = None;
            store
                .election_admission
                .observe_credentials(&store.raft, true);
        }
    }
}

/// Whether the local credentials admit connections to enough peers for this
/// voter, counted with its own vote, to form a quorum of current voters.
/// `None` keeps the previous admission while the directory is unavailable.
fn local_credentials_admit_election(store: &ConsensusSessionStoreInner) -> Option<bool> {
    let (_, peers) = store.peer_directory.current_peers().ok()?;
    let voters = peers.len().checked_add(1)?;
    let admitted = peers
        .values()
        .filter(|peer| peer.local_credentials_admit_connections())
        .count()
        .checked_add(1)?;
    Some(admitted > voters / 2)
}
