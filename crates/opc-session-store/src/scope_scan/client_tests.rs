use super::*;
use crate::scope_authority::tests::{admitted, successor};
use crate::scope_batch::tests::{key, value};
use crate::scope_batch::{ScopeBatchCheckpoint, ScopeChildRecord, ScopeChildRevision};
use crate::scope_scan::{
    engine::{InventoryBudget, InventoryError, InventorySource},
    headers::RawScopeRecord,
    integrity::ItemKind,
    progress::InventoryTotals,
    protocol::{PageProtocol, ReplyBody},
};
use crate::scope_storage::{self, ScopeRow};
use crate::SessionKey;
use opc_consensus::engine::{CommittedLeaderId, LogId};
use std::{collections::VecDeque, sync::Mutex, time::Duration};
use tokio::time::Instant;

struct Source {
    exhausted: bool,
}
impl InventorySource for Source {
    fn next_candidate(
        &mut self,
        ns: &crate::scope_authority::ScopeNamespace,
        kind: ItemKind,
        after: Option<&crate::scope_scan::engine::InventoryPosition>,
        budget: &mut InventoryBudget,
    ) -> Result<Option<crate::scope_scan::engine::InventoryCandidate>, InventoryError> {
        if self.exhausted {
            return Err(InventoryError::WorkBudget);
        }
        budget.charge(512)?;
        if kind != ItemKind::Child {
            return Ok(None);
        }
        Ok([1, 2]
            .into_iter()
            .map(|n| scope_storage::child_key(ns, key(n)).unwrap())
            .map(|key| crate::scope_scan::engine::native_candidate(ns, key).unwrap())
            .find(|candidate| after.is_none_or(|after| candidate.position > *after)))
    }
    fn read(
        &mut self,
        physical: &SessionKey,
        budget: &mut InventoryBudget,
    ) -> Result<RawScopeRecord, InventoryError> {
        budget.charge(512)?;
        let first = admitted();
        let after = first.transition(&successor(&first, 2)).unwrap();
        let ns = after.view.stamp().unwrap().namespace();
        let n = physical.stable_id.as_ref()[63];
        let row = ScopeRow::Child(ScopeChildRecord {
            namespace: ns.clone(),
            key: key(n),
            revision: ScopeChildRevision::new(n as u64, 1).unwrap(),
            batch_revision: 1,
            value: Some(value(n)),
            claims: vec![],
        })
        .to_record()
        .unwrap();
        budget.charge(row.payload.len())?;
        Ok(RawScopeRecord::Present(row))
    }
}
struct View {
    cut: ScopeCut,
    authority: ScopeAuthorityView,
    checkpoint: ScopeScanCheckpoint,
    cursor: ScopeScanCursor,
    protocol: Mutex<PageProtocol>,
}
impl ScopeScanClientView for View {
    fn cut(&self) -> &ScopeCut {
        &self.cut
    }
    fn authority(&self) -> &ScopeAuthorityView {
        &self.authority
    }
    fn checkpoint(&self) -> &ScopeScanCheckpoint {
        &self.checkpoint
    }
    fn initial_cursor(&self) -> &ScopeScanCursor {
        &self.cursor
    }
}
#[derive(Clone, Copy)]
enum Action {
    Pass,
    LostReply,
    Unavailable,
    Restart,
    Work,
    WrongCut,
    WrongTotals,
    Final,
    Pending,
}
#[derive(Default)]
struct Observed {
    opens: Vec<(Option<SessionConsensusNodeId>, usize)>,
    requests: Vec<(u8, Vec<u8>, Instant)>,
    closed: usize,
}
struct Port {
    actions: Mutex<VecDeque<Action>>,
    open_failures: Mutex<usize>,
    open_delay: Duration,
    observed: Arc<Mutex<Observed>>,
    events: Arc<Mutex<Vec<&'static str>>>,
}
#[async_trait]
impl ScopeScanTransport for Port {
    type View = View;
    async fn open(
        &self,
        preferred: Option<SessionConsensusNodeId>,
        limits: ScopeScanPageLimits,
    ) -> Result<View, ScopeScanRequestFailure> {
        self.events.lock().unwrap().push("open");
        let n = {
            let mut obs = self.observed.lock().unwrap();
            obs.opens.push((preferred, limits.rows()));
            obs.opens.len() as u8
        };
        {
            let mut fail = self.open_failures.lock().unwrap();
            if *fail > 0 {
                *fail -= 1;
                return Err(ScopeScanRequestFailure::Retryable(
                    ScopeScanRetryCause::Unavailable,
                ));
            }
        }
        if !self.open_delay.is_zero() {
            sleep(self.open_delay).await;
        }
        let first = admitted();
        let after = first.transition(&successor(&first, 2)).unwrap();
        let stamp = after.view.stamp().unwrap();
        let node = SessionConsensusNodeId::new(7).unwrap();
        let cut = ScopeCut {
            namespace: stamp.namespace().clone(),
            authority_revision: stamp.revision(),
            batch_revision: 1,
            applied: LogId::new(CommittedLeaderId::new(1, node), 1),
            epoch: 1,
            capture_id: [n; 16],
            serving_node: node,
        };
        let (protocol, cursor) = PageProtocol::new(cut.clone(), stamp, 2, limits.0).unwrap();
        let mut checkpoint = ScopeBatchCheckpoint::empty(stamp.scope().clone());
        checkpoint.revision = 1;
        checkpoint.birth_floor = 2;
        Ok(View {
            cut,
            authority: after.view,
            checkpoint: checkpoint.into(),
            cursor,
            protocol: Mutex::new(protocol),
        })
    }
    async fn page(
        &self,
        view: &View,
        cursor: &ScopeScanCursor,
    ) -> Result<Arc<ScopeScanReply>, ScopeScanRequestFailure> {
        self.observed.lock().unwrap().requests.push((
            view.cut.capture_id[0],
            cursor.as_bytes().to_vec(),
            Instant::now(),
        ));
        let action = self
            .actions
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Action::Pass);
        match action {
            Action::Unavailable => {
                return Err(ScopeScanRequestFailure::Retryable(
                    ScopeScanRetryCause::Unavailable,
                ))
            }
            Action::Restart => {
                return Err(ScopeScanRequestFailure::Retryable(
                    ScopeScanRetryCause::SnapshotInstalled,
                ))
            }
            Action::Final => {
                return Err(ScopeScanRequestFailure::Final(ScopeScanError::Unauthorized))
            }
            Action::Pending => return std::future::pending().await,
            Action::WrongCut | Action::WrongTotals => {
                let mut cut = view.cut.clone();
                if matches!(action, Action::WrongCut) {
                    cut.capture_id[0] ^= 128;
                }
                return Ok(Arc::new(ScopeScanReply {
                    cut,
                    body: ReplyBody::Complete {
                        totals: InventoryTotals {
                            items: if matches!(action, Action::WrongCut) {
                                1
                            } else {
                                1000
                            },
                            ..InventoryTotals::default()
                        },
                        manifest: None,
                    },
                }));
            }
            _ => {}
        }
        let result = view
            .protocol
            .lock()
            .unwrap()
            .page(
                cursor,
                &mut Source {
                    exhausted: matches!(action, Action::Work),
                },
            )
            .map_err(ScopeScanRequestFailure::Final)?;
        if matches!(action, Action::LostReply) {
            return Err(ScopeScanRequestFailure::Retryable(
                ScopeScanRetryCause::Unavailable,
            ));
        }
        Ok(result)
    }
    async fn close(&self, _view: View) {
        self.observed.lock().unwrap().closed += 1;
        self.events.lock().unwrap().push("close");
    }
}
struct Sink {
    events: Arc<Mutex<Vec<&'static str>>>,
    staged: usize,
    begins: usize,
    discarded: usize,
    fail: bool,
    pending: bool,
}
#[async_trait]
impl ScopeScanSink for Sink {
    type Error = &'static str;
    type Output = usize;
    async fn begin(
        &mut self,
        _: &ScopeCut,
        _: &ScopeAuthorityView,
        _: &ScopeScanCheckpoint,
    ) -> Result<(), Self::Error> {
        self.begins += 1;
        self.events.lock().unwrap().push("begin");
        Ok(())
    }
    async fn stage(&mut self, reply: &ScopeScanReply) -> Result<(), Self::Error> {
        self.events.lock().unwrap().push("stage");
        self.staged += reply.items().len();
        if self.pending {
            return std::future::pending().await;
        }
        if self.fail {
            return Err("staging failed");
        }
        Ok(())
    }
    async fn finish(&mut self, reply: &ScopeScanReply) -> Result<usize, Self::Error> {
        assert!(reply.summary().is_some());
        self.events.lock().unwrap().push("finish");
        Ok(self.staged)
    }
    fn discard(&mut self, _: &ScopeCut) {
        self.discarded += 1;
        self.staged = 0;
        self.events.lock().unwrap().push("discard");
    }
}
fn fixture(
    actions: &[Action],
    attempts: u32,
    rows: usize,
) -> (ScopeScanClient<Port>, Sink, Arc<Mutex<Observed>>) {
    let observed = Arc::new(Mutex::new(Observed::default()));
    let events = Arc::new(Mutex::new(vec![]));
    let port = Port {
        actions: Mutex::new(actions.iter().copied().collect()),
        open_failures: Mutex::new(0),
        open_delay: Duration::ZERO,
        observed: Arc::clone(&observed),
        events: Arc::clone(&events),
    };
    let client = ScopeScanClient::new(port).with_limits(
        ScopeScanPageLimits::new(rows, crate::RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES).unwrap(),
        ScopeScanRetryPolicy::new(attempts, Duration::from_millis(25), Duration::from_secs(1))
            .unwrap(),
    );
    let sink = Sink {
        events,
        staged: 0,
        begins: 0,
        discarded: 0,
        fail: false,
        pending: false,
    };
    (client, sink, observed)
}
#[tokio::test(start_paused = true)]
async fn scope_scan_client_lost_reply_retries_exact_cursor_before_acknowledging() {
    let (client, mut sink, obs) = fixture(&[Action::LostReply, Action::Unavailable], 16, 1);
    assert_eq!(
        client
            .restore(
                &mut sink,
                tokio::time::Instant::now() + Duration::from_secs(60)
            )
            .await
            .unwrap(),
        2
    );
    let obs = obs.lock().unwrap();
    assert_eq!(obs.opens.len(), 1);
    assert_eq!(obs.closed, 1);
    assert_eq!(obs.requests[0].1, obs.requests[1].1);
    assert_eq!(obs.requests[1].1, obs.requests[2].1);
    assert_ne!(obs.requests[2].1, obs.requests[3].1);
    assert_eq!(sink.discarded, 0);
    assert_eq!(
        obs.requests[1].2 - obs.requests[0].2,
        Duration::from_millis(25)
    );
    assert_eq!(
        obs.requests[2].2 - obs.requests[1].2,
        Duration::from_millis(50)
    );
}
#[tokio::test(start_paused = true)]
async fn scope_scan_client_discards_old_cut_before_sticky_reopen() {
    let (client, mut sink, obs) = fixture(&[Action::Pass, Action::Restart], 16, 1);
    assert_eq!(
        client
            .restore(
                &mut sink,
                tokio::time::Instant::now() + Duration::from_secs(60)
            )
            .await
            .unwrap(),
        2
    );
    let obs = obs.lock().unwrap();
    assert_eq!(obs.opens.len(), 2);
    assert_eq!(obs.opens[0].0, None);
    assert_eq!(
        obs.opens[1].0,
        Some(SessionConsensusNodeId::new(7).unwrap())
    );
    assert_eq!(obs.closed, 2);
    assert_eq!(sink.discarded, 1);
    assert_eq!(sink.begins, 2);
    let events = sink.events.lock().unwrap();
    let discard = events.iter().position(|e| *e == "discard").unwrap();
    let reopen = events
        .iter()
        .enumerate()
        .filter(|(_, e)| **e == "open")
        .nth(1)
        .unwrap()
        .0;
    assert!(discard < reopen);
}
#[tokio::test(start_paused = true)]
async fn scope_scan_client_progress_and_new_cuts_never_reset_the_lifetime_budget() {
    let (client, mut sink, obs) = fixture(
        &[
            Action::Pass,
            Action::Unavailable,
            Action::Pass,
            Action::Restart,
            Action::Pass,
            Action::Unavailable,
            Action::Pass,
            Action::Restart,
        ],
        4,
        1,
    );
    let Err(ScopeScanClientError::Stalled(stalled)) = client
        .restore(
            &mut sink,
            tokio::time::Instant::now() + Duration::from_secs(60),
        )
        .await
    else {
        panic!("restore must stop at the shared budget")
    };
    assert_eq!(stalled.attempts(), 4);
    assert_eq!(stalled.attempts_for(ScopeScanRetryCause::Unavailable), 2);
    assert_eq!(
        stalled.attempts_for(ScopeScanRetryCause::SnapshotInstalled),
        2
    );
    assert_eq!(obs.lock().unwrap().opens.len(), 2);
    assert_eq!(sink.discarded, 2);
    assert_eq!(sink.staged, 0);
}
#[tokio::test(start_paused = true)]
async fn scope_scan_client_reduced_limit_survives_reopen_and_work_replies_are_acknowledged() {
    let (client, mut sink, obs) = fixture(&[Action::Work, Action::Work, Action::Restart], 16, 256);
    assert_eq!(
        client
            .restore(
                &mut sink,
                tokio::time::Instant::now() + Duration::from_secs(60)
            )
            .await
            .unwrap(),
        2
    );
    let obs = obs.lock().unwrap();
    assert_eq!(obs.opens[1].1, 64);
    assert_ne!(obs.requests[0].1, obs.requests[1].1);
    assert_ne!(obs.requests[1].1, obs.requests[2].1);
    assert_eq!(sink.discarded, 1);
}
#[tokio::test(start_paused = true)]
async fn scope_scan_client_one_row_no_progress_stalls_with_capped_backoff() {
    let (client, mut sink, obs) = fixture(&[Action::Work; 16], 16, 1);
    let Err(ScopeScanClientError::Stalled(stalled)) = client
        .restore(
            &mut sink,
            tokio::time::Instant::now() + Duration::from_secs(60),
        )
        .await
    else {
        panic!("no-progress restore escaped its bound")
    };
    assert_eq!(stalled.attempts(), 16);
    assert_eq!(
        stalled.attempts_for(ScopeScanRetryCause::WorkBudgetExceeded),
        16
    );
    let obs = obs.lock().unwrap();
    assert_eq!(obs.opens.len(), 1);
    assert_eq!(obs.requests.len(), 16);
    assert_eq!(obs.closed, 1);
    for (i, pair) in obs.requests.windows(2).enumerate() {
        assert_eq!(
            pair[1].2 - pair[0].2,
            Duration::from_millis((25u64 << i).min(1000))
        );
    }
}
#[tokio::test(start_paused = true)]
async fn scope_scan_client_repeated_open_failure_has_the_same_finite_budget() {
    let (client, mut sink, obs) = fixture(&[], 3, 1);
    *client.transport.open_failures.lock().unwrap() = usize::MAX;
    let Err(ScopeScanClientError::Stalled(stalled)) = client
        .restore(
            &mut sink,
            tokio::time::Instant::now() + Duration::from_secs(60),
        )
        .await
    else {
        panic!("unavailable opening loop did not stop")
    };
    assert_eq!(stalled.attempts(), 3);
    assert_eq!(obs.lock().unwrap().opens.len(), 3);
    assert_eq!(sink.begins, 0);
}
#[tokio::test(start_paused = true)]
async fn scope_scan_client_final_refusal_and_wrong_cut_stop_without_retry() {
    for action in [Action::Final, Action::WrongCut, Action::WrongTotals] {
        let (client, mut sink, obs) = fixture(&[Action::Pass, action], 16, 1);
        match (
            action,
            client
                .restore(
                    &mut sink,
                    tokio::time::Instant::now() + Duration::from_secs(60),
                )
                .await,
        ) {
            (Action::Final, Err(ScopeScanClientError::Request(ScopeScanError::Unauthorized))) => {}
            (Action::WrongCut | Action::WrongTotals, Err(ScopeScanClientError::InvalidReply)) => {}
            _ => panic!("final failure was not classified"),
        }
        let obs = obs.lock().unwrap();
        assert_eq!(obs.requests.len(), 2);
        assert_eq!(obs.closed, 1);
        assert_eq!(sink.discarded, 1);
    }
}
#[tokio::test(start_paused = true)]
async fn scope_scan_client_staging_error_discards_and_closes_without_acknowledging() {
    let (client, mut sink, obs) = fixture(&[], 16, 1);
    sink.fail = true;
    assert!(matches!(
        client
            .restore(
                &mut sink,
                tokio::time::Instant::now() + Duration::from_secs(60)
            )
            .await,
        Err(ScopeScanClientError::Sink("staging failed"))
    ));
    let obs = obs.lock().unwrap();
    assert_eq!(obs.requests.len(), 1);
    assert_eq!(obs.closed, 1);
    assert_eq!(sink.discarded, 1);
}
#[tokio::test(start_paused = true)]
async fn scope_scan_client_future_cancellation_discards_partial_staging() {
    let (client, mut sink, obs) = fixture(&[], 16, 1);
    sink.pending = true;
    let mut restore = Box::pin(client.restore(
        &mut sink,
        tokio::time::Instant::now() + Duration::from_secs(60),
    ));
    assert!(futures_util::poll!(restore.as_mut()).is_pending());
    drop(restore);
    assert_eq!(sink.discarded, 1);
    assert_eq!(sink.staged, 0);
    assert_eq!(obs.lock().unwrap().requests.len(), 1);
}
#[tokio::test(start_paused = true)]
async fn scope_scan_client_queued_open_keeps_one_request_without_spending_retries() {
    let (mut client, mut sink, obs) = fixture(&[], 1, 1);
    client.transport.open_delay = Duration::from_secs(45);
    let result = timeout(
        Duration::from_secs(60),
        client.restore(
            &mut sink,
            tokio::time::Instant::now() + Duration::from_secs(60),
        ),
    )
    .await
    .expect("restore did not finish before its deadline");
    assert!(result.is_ok(), "queued open consumed recovery: {result:?}");
    assert_eq!(obs.lock().unwrap().opens.len(), 1);
    assert_eq!(sink.begins, 1);
    assert_eq!(sink.discarded, 0);
}

#[tokio::test(start_paused = true)]
async fn scope_scan_client_pending_request_ends_at_restore_deadline_without_retry() {
    let (client, mut sink, obs) = fixture(&[Action::Pending, Action::Pending], 2, 1);
    let deadline = Instant::now() + Duration::from_secs(25);
    let Err(ScopeScanClientError::DeadlineElapsed) = client.restore(&mut sink, deadline).await
    else {
        panic!("pending page bypassed request deadline")
    };
    assert_eq!(Instant::now(), deadline);
    let obs = obs.lock().unwrap();
    assert_eq!(obs.opens.len(), 1);
    assert_eq!(obs.requests.len(), 1);
    assert_eq!(sink.discarded, 1);
    assert_eq!(sink.staged, 0);
}

#[tokio::test(start_paused = true)]
async fn scope_scan_client_queued_open_ends_only_at_restore_deadline() {
    let (mut client, mut sink, obs) = fixture(&[], 1, 1);
    client.transport.open_delay = Duration::from_secs(45);
    let deadline = Instant::now() + Duration::from_secs(35);
    assert!(matches!(
        client.restore_until(&mut sink, deadline).await,
        Err(ScopeScanClientError::DeadlineElapsed)
    ));
    assert_eq!(Instant::now(), deadline);
    assert_eq!(obs.lock().unwrap().opens.len(), 1);
    assert_eq!(sink.begins, 0);
}

#[tokio::test(start_paused = true)]
async fn scope_scan_client_expired_deadline_starts_no_request_or_staging() {
    let (client, mut sink, obs) = fixture(&[], 1, 1);
    assert!(matches!(
        client.restore(&mut sink, Instant::now()).await,
        Err(ScopeScanClientError::DeadlineElapsed)
    ));
    assert!(obs.lock().unwrap().opens.is_empty());
    assert_eq!(sink.begins, 0);
    assert_eq!(sink.discarded, 0);
}
