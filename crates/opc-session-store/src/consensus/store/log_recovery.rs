//! A stalled snapshot owner cannot retain a full leader admission window.

use super::*;
use opc_consensus::engine::ServerState;

pub(super) fn start(inner: &Arc<ConsensusSessionStoreInner>) {
    let weak = Arc::downgrade(inner);
    let mut metrics = inner.raft.metrics();
    let mut pressure_changes = inner.raft_handler.log_admission.changes();
    let mut active_changes = inner.persistence_protocol.active_changes();
    tokio::spawn(async move {
        let mut progress = None;
        let mut full_since = None;
        let mut target = None;
        let mut handoff = None;
        let mut next_attempt = tokio::time::Instant::now();
        loop {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            if inner.retirement.is_started()
                || inner
                    .shutdown
                    .completion
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_some()
            {
                return;
            }
            let (leader, vote, frontier) = {
                let current = metrics.borrow_and_update();
                if current.running_state.is_err() {
                    return;
                }
                (
                    current.state == ServerState::Leader
                        && current.current_leader == Some(inner.local_node_id),
                    current.vote,
                    (current.snapshot, current.purged),
                )
            };
            let now = tokio::time::Instant::now();
            let previous = progress.replace((vote, frontier));
            if previous.is_none_or(|previous| previous.0 != vote) || !leader {
                target = None;
                handoff = None;
                full_since = None;
            }
            let full = !inner.raft_handler.log_admission.has_capacity();
            let active = inner.persistence_protocol.is_active();
            if !leader || !active || !full {
                full_since = None;
            } else if previous != Some((vote, frontier)) || full_since.is_none() {
                // Only a snapshot/purge frontier, a new vote, or actual spare
                // capacity resets the bound. Heartbeats and new appends do not.
                full_since = Some(now);
            }
            let due =
                full_since.map(|since| since + inner.storage_shutdown.snapshot_pressure_timeout());
            let transfer_due = handoff.is_some() || due.is_some_and(|due| now >= due);
            if leader && active && transfer_due && now >= next_attempt {
                let store = ConsensusSessionStore { inner };
                let deadline = store.operation_deadline_from(now);
                let result = tokio::time::timeout_at(
                    deadline,
                    store.transfer_pressure_leadership_before(&mut target, &mut handoff, deadline),
                )
                .await;
                if !matches!(result, Ok(Ok(()))) {
                    tracing::warn!("snapshot pressure leadership transfer will retry");
                }
                // Keep an accepted target/request across a failed completion.
                // A failed begin owns neither and still requires live pressure.
                next_attempt = tokio::time::Instant::now() + Duration::from_secs(1);
                continue;
            }
            let wake = if !leader || !active {
                None
            } else if transfer_due {
                Some(next_attempt)
            } else {
                due
            };
            drop(inner);
            tokio::select! {
                changed = metrics.changed() => if changed.is_err() { return; },
                changed = pressure_changes.changed() => if changed.is_err() { return; },
                changed = active_changes.changed() => if changed.is_err() { return; },
                () = async {
                    if let Some(wake) = wake {
                        tokio::time::sleep_until(wake).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {},
            }
        }
    });
}
