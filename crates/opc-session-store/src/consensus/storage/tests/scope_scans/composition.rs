//! Real backend captures and snapshot installation composed with the restore
//! driver. Quorum/boot admission is covered by the separate facade/TLS tests.

use super::*;
use crate::consensus::types::fenced_transition_voter_set_digest;
use crate::scope_authority::{
    ScopeAuthorityCommand, ScopeAuthorityOperation, ScopeAuthorityRequest, ScopeAuthorityStamp,
    ScopeAuthorityView, ScopeClosureEvidence, ScopeClosureKind, ScopeId, ScopeProfileActivation,
    ScopeState,
};
use crate::scope_batch::{ScopeBatchCommand, ScopeBatchRequest, ScopeCounterMutation};
use crate::scope_scan::{
    engine::{
        InventoryBudget, InventoryCandidate, InventoryError, InventoryPosition, InventorySource,
    },
    headers::{decode_headers_with_handover, RawScopeRecord},
    integrity::ItemKind,
    protocol::PageProtocol,
    sources::{NativeSource, SqliteSource},
    ScopeCut, ScopeScanCheckpoint, ScopeScanClient, ScopeScanClientError, ScopeScanClientView,
    ScopeScanCursor, ScopeScanError, ScopeScanPageLimits, ScopeScanPageStatus, ScopeScanReply,
    ScopeScanRequestFailure, ScopeScanRetryCause, ScopeScanRetryPolicy, ScopeScanSink,
    ScopeScanTransport,
};
use crate::sqlite::scope_scan::read_raw_record;
use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

type Advance = oneshot::Sender<()>;

struct RestoreView {
    retained: View,
    cut: ScopeCut,
    authority: ScopeAuthorityView,
    checkpoint: ScopeScanCheckpoint,
    cursor: ScopeScanCursor,
}
impl ScopeScanClientView for RestoreView {
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

#[derive(Default)]
struct Observed {
    openings: AtomicUsize,
    no_progress: AtomicUsize,
    partial_pages: AtomicUsize,
}
struct Port {
    core: SqliteConsensusCore,
    scheduler: ScopeScheduler,
    stamp: ScopeAuthorityStamp,
    succession: ScopeAuthorityRequest,
    advance: tokio::sync::mpsc::UnboundedSender<Advance>,
    installation: Arc<tokio::sync::Mutex<()>>,
    first_slow_read: AtomicBool,
    observed: Arc<Observed>,
}
fn retry(cause: ScopeScanRetryCause) -> ScopeScanRequestFailure {
    ScopeScanRequestFailure::Retryable(cause)
}
fn changed() -> ScopeScanRequestFailure {
    retry(ScopeScanRetryCause::SnapshotInstalled)
}

// Deterministic slow I/O: completing one real row consumes the page's work
// deadline. Later source queries observe that same exhausted budget, including
// SQLite's production VM hook. No wall-clock sleep or fake row is involved.
struct Slow<S> {
    source: S,
    exhausted: Arc<AtomicBool>,
}
impl<S: InventorySource> InventorySource for Slow<S> {
    fn next_candidate(
        &mut self,
        namespace: &crate::scope_authority::ScopeNamespace,
        kind: ItemKind,
        after: Option<&InventoryPosition>,
        budget: &mut InventoryBudget,
    ) -> Result<Option<InventoryCandidate>, InventoryError> {
        self.source.next_candidate(namespace, kind, after, budget)
    }
    fn read(
        &mut self,
        key: &crate::SessionKey,
        budget: &mut InventoryBudget,
    ) -> Result<RawScopeRecord, InventoryError> {
        let result = self.source.read(key, budget);
        self.exhausted.store(true, Ordering::SeqCst);
        result
    }
}

#[async_trait]
impl ScopeScanTransport for Port {
    type View = RestoreView;
    async fn open(
        &self,
        preferred: Option<SessionConsensusNodeId>,
        limits: ScopeScanPageLimits,
    ) -> Result<RestoreView, ScopeScanRequestFailure> {
        // The coordinator makes its transport available again when an
        // installation finishes. A tiny test backoff must not consume every
        // retry merely because that one storage operation is still running.
        // Never keep this gate while waiting for a retained-view credit.
        drop(self.installation.lock().await);
        let serving_node = SessionConsensusNodeId::new(1).unwrap();
        assert!(preferred.is_none_or(|node| node == serving_node));
        let registry = Arc::clone(&self.core.scope_views);
        let wal = self
            .core
            .private_wal
            .as_ref()
            .filter(|wal| wal.is_native())
            .cloned();
        let source = self.core.database_file.clone().unwrap();
        let identity = self.core.storage_identity;
        let cost = if let Some(wal) = wal.as_ref() {
            CaptureCost::Native(wal.native_scope_cost(&|| Ok(())).map_err(|_| changed())? as u64)
        } else {
            let conn = self.core.conn.lock().await;
            registry.observe_wal(Some(
                opc_sqlite_file_control_sys::main_journal_descriptor(&conn)
                    .unwrap()
                    .metadata()
                    .unwrap()
                    .len(),
            ));
            CaptureCost::Sqlite
        };
        let retained = registry
            .admit(
                key(),
                cost,
                None,
                self.scheduler
                    .reserve(key(), ScopeWorkClass::Normal)
                    .await
                    .unwrap(),
            )
            .await
            .map_err(|_| changed())?;
        let reservation = retained.reservation.clone();
        let epoch = retained.epoch;
        let stamp = self.stamp.clone();
        let succession = self.succession.clone();
        let capture_id =
            (self.observed.openings.fetch_add(1, Ordering::SeqCst) as u128 + 1).to_be_bytes();
        let operation = retained
            .runtime
            .start_normal(move |slot, cancelled| {
                let check = || {
                    if cancelled.is_cancelled() {
                        Err(io::Error::other("capture revoked"))
                    } else {
                        Ok(())
                    }
                };
                let backend = if let Some(wal) = wal {
                    let capture = wal
                        .native_scope_capture(&check, |bytes| {
                            registry
                                .adjust_native_cost(&reservation, bytes as u64)
                                .map_err(io::Error::other)
                        })?
                        .ok_or_else(|| io::Error::other("capture cost changed"))?;
                    CapturedBackend::Native {
                        owner: Arc::downgrade(&wal),
                        capture: Box::new(capture),
                    }
                } else {
                    CapturedBackend::Sqlite(Box::new(SqliteScopeScan::capture(
                        &source, identity, &check,
                    )?))
                };
                let namespace = stamp.namespace();
                let (applied, headers) = match &backend {
                    CapturedBackend::Native { owner, capture } => {
                        let headers = owner
                            .upgrade()
                            .unwrap()
                            .native_scope_read(capture, &check, |rows, _| {
                                Ok(decode_headers_with_handover(
                                    namespace,
                                    &stamp,
                                    Some(&succession),
                                    |key, maximum| {
                                        Ok(RawScopeRecord::from_native(
                                            rows.records().get(key),
                                            maximum,
                                        ))
                                    },
                                ))
                            })?
                            .map_err(io::Error::other)?;
                        (capture.applied().unwrap(), headers)
                    }
                    CapturedBackend::Sqlite(capture) => {
                        let headers = capture
                            .read(
                                || false,
                                |conn, _| {
                                    Ok(decode_headers_with_handover(
                                        namespace,
                                        &stamp,
                                        Some(&succession),
                                        |key, maximum| {
                                            read_raw_record(conn, key, maximum)
                                                .map_err(|_| ScopeScanError::Unavailable)
                                        },
                                    ))
                                },
                            )?
                            .map_err(io::Error::other)?;
                        (capture.applied().unwrap(), headers)
                    }
                };
                let cut = ScopeCut {
                    namespace: namespace.clone(),
                    authority_revision: stamp.revision(),
                    batch_revision: headers.checkpoint.revision,
                    applied,
                    epoch,
                    capture_id,
                    serving_node,
                };
                let (protocol, cursor) = PageProtocol::new(
                    cut.clone(),
                    &stamp,
                    headers.checkpoint.birth_floor,
                    limits.0,
                )
                .map_err(io::Error::other)?;
                *slot = Some(CapturedScope { backend, protocol });
                Ok::<_, io::Error>((cut, headers.authority, headers.checkpoint.into(), cursor))
            })
            .map_err(|_| changed())?;
        let (cut, authority, checkpoint, cursor) = operation
            .result()
            .await
            .map_err(|_| changed())?
            .map_err(|_| changed())?;
        Ok(RestoreView {
            retained,
            cut,
            authority,
            checkpoint,
            cursor,
        })
    }

    async fn page(
        &self,
        view: &RestoreView,
        cursor: &ScopeScanCursor,
    ) -> Result<Arc<ScopeScanReply>, ScopeScanRequestFailure> {
        let (advance, advanced) = oneshot::channel();
        self.advance.send(advance).unwrap();
        advanced.await.unwrap();
        let exhausted = Arc::new(AtomicBool::new(
            self.first_slow_read.swap(false, Ordering::SeqCst),
        ));
        let cursor = cursor.clone();
        let operation = view
            .retained
            .runtime
            .start_normal(move |slot, cancelled| {
                let captured = slot.as_mut().unwrap();
                let protocol = &mut captured.protocol;
                match &captured.backend {
                    CapturedBackend::Native { owner, capture } => {
                        let check = || {
                            if cancelled.is_cancelled() {
                                Err(io::Error::other("page revoked"))
                            } else {
                                Ok(())
                            }
                        };
                        let work_exhausted = || exhausted.load(Ordering::SeqCst);
                        owner.upgrade().unwrap().native_scope_read(
                            capture,
                            &check,
                            |rows, current| {
                                let source = NativeSource {
                                    capture: rows,
                                    check: current,
                                    work_exhausted: &work_exhausted,
                                };
                                Ok(protocol.page(
                                    &cursor,
                                    &mut Slow {
                                        source,
                                        exhausted: Arc::clone(&exhausted),
                                    },
                                ))
                            },
                        )
                    }
                    CapturedBackend::Sqlite(capture) => {
                        let work = Arc::clone(&exhausted);
                        let cancelled = cancelled.clone();
                        capture.read_bounded(
                            move || cancelled.is_cancelled(),
                            move || work.load(Ordering::SeqCst),
                            |conn, check, work_exhausted| {
                                let source = SqliteSource {
                                    connection: conn,
                                    check,
                                    work_exhausted,
                                };
                                Ok(protocol.page(
                                    &cursor,
                                    &mut Slow {
                                        source,
                                        exhausted: Arc::clone(&exhausted),
                                    },
                                ))
                            },
                        )
                    }
                }
            })
            .map_err(|_| changed())?;
        let reply = operation
            .result()
            .await
            .map_err(|_| changed())?
            .map_err(|_| changed())?
            .map_err(ScopeScanRequestFailure::Final)?;
        match reply.status() {
            ScopeScanPageStatus::WorkBudgetExceeded => {
                self.observed.no_progress.fetch_add(1, Ordering::SeqCst);
            }
            ScopeScanPageStatus::Progress => {
                assert_eq!(
                    reply.items().len(),
                    1,
                    "slow work returns its complete prefix"
                );
                self.observed.partial_pages.fetch_add(1, Ordering::SeqCst);
            }
            ScopeScanPageStatus::Complete => {}
        }
        Ok(reply)
    }
    async fn close(&self, view: RestoreView) {
        view.retained
            .runtime
            .close_and_drain(ViewInvalidation::Closed)
            .await;
    }
}

#[derive(Default)]
struct Sink {
    cut: Option<ScopeCut>,
    staged: usize,
    discarded: usize,
}
#[async_trait]
impl ScopeScanSink for Sink {
    type Error = std::convert::Infallible;
    type Output = usize;
    async fn begin(
        &mut self,
        cut: &ScopeCut,
        _: &ScopeAuthorityView,
        checkpoint: &ScopeScanCheckpoint,
    ) -> Result<(), Self::Error> {
        assert!(self.cut.is_none());
        assert_eq!(checkpoint.revision(), cut.batch_revision());
        self.cut = Some(cut.clone());
        self.staged = 0;
        Ok(())
    }
    async fn stage(&mut self, reply: &ScopeScanReply) -> Result<(), Self::Error> {
        assert_eq!(self.cut.as_ref(), Some(reply.cut()));
        for item in reply.items() {
            assert!(item.failures().is_empty());
            assert!(item.child().unwrap().batch_revision <= reply.cut().batch_revision());
            self.staged += 1;
        }
        Ok(())
    }
    async fn finish(&mut self, reply: &ScopeScanReply) -> Result<usize, Self::Error> {
        assert_eq!(self.cut.as_ref(), Some(reply.cut()));
        assert_eq!(reply.summary().unwrap().examined_items(), 4);
        assert_eq!(self.staged, 4);
        self.cut = None;
        Ok(self.staged)
    }
    fn discard(&mut self, cut: &ScopeCut) {
        assert_eq!(self.cut.as_ref(), Some(cut));
        self.cut = None;
        self.staged = 0;
        self.discarded += 1;
    }
}

fn authorized(index: u64, intent: SessionMutationIntent) -> Entry<SessionRaftTypeConfig> {
    let request_id = match &intent {
        SessionMutationIntent::ScopeAuthority(command) => *command.request.request_id(),
        SessionMutationIntent::ScopeBatch(command) => *command.request.request_id(),
        _ => (0x1000 + u128::from(index)).to_be_bytes(),
    };
    normal_entry(
        index,
        SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(1),
            request_id: SessionConsensusRequestId::from_bytes(request_id),
            logical_time: timestamp(1),
            intent: SessionMutationIntent::Authorized {
                origin: *fixed_raw_read_members().first().unwrap(),
                authority_identity: identity(1),
                mutation: Box::new(intent),
            },
        },
    )
}

async fn assert_installed_scope(
    core: &SqliteConsensusCore,
    stamp: &ScopeAuthorityStamp,
    succession: &ScopeAuthorityRequest,
    writes: u64,
) {
    let profile = crate::scope_storage::profile_key(identity(1).cluster_id()).unwrap();
    let check_profile = |record: &crate::StoredSessionRecord| {
        let crate::scope_storage::ScopeRow::Activation(certificate) =
            crate::scope_storage::ScopeRow::from_record(record).unwrap()
        else {
            panic!("scope profile keeps its row kind")
        };
        assert!(certificate.matches(
            identity(1),
            fenced_transition_voter_set_digest(identity(1), &fixed_raw_read_members()),
        ));
    };
    let headers = if let Some(wal) = core.private_wal.as_ref().filter(|wal| wal.is_native()) {
        let capture = wal
            .native_scope_capture(&|| Ok(()), |_| Ok(true))
            .unwrap()
            .unwrap();
        wal.native_scope_read(&capture, &|| Ok(()), |rows, _| {
            check_profile(
                rows.records()
                    .get(&profile)
                    .expect("scope profile survives installation"),
            );
            Ok(decode_headers_with_handover(
                stamp.namespace(),
                stamp,
                Some(succession),
                |key, maximum| {
                    Ok(RawScopeRecord::from_native(
                        rows.records().get(key),
                        maximum,
                    ))
                },
            ))
        })
        .unwrap()
        .unwrap()
    } else {
        let conn = core.conn.lock().await;
        let RawScopeRecord::Present(record) =
            read_raw_record(&conn, &profile, crate::scope_storage::MAX_METADATA_BYTES).unwrap()
        else {
            panic!("scope profile survives installation")
        };
        check_profile(&record);
        decode_headers_with_handover(
            stamp.namespace(),
            stamp,
            Some(succession),
            |key, maximum| {
                read_raw_record(&conn, key, maximum).map_err(|_| ScopeScanError::Unavailable)
            },
        )
        .unwrap()
    };
    assert_eq!(headers.authority.stamp(), Some(stamp));
    assert_eq!(headers.checkpoint.revision, writes + 1);
    assert_eq!(headers.checkpoint.birth_floor, 4);
    assert_eq!(headers.checkpoint.counters[0], writes);
}

async fn composed(native: bool, continuous_installs: bool) {
    let directory = portable_fixed_fixture();
    let wal = token(&directory, native);
    let (_backend, mut log, mut machine) = open_private_snapshot_store_with_integrity(
        &directory,
        Arc::clone(&wal),
        SnapshotIntegrityPolicy::PortableVerified,
    )
    .await
    .unwrap();
    let scope = ScopeId::new(
        identity(1),
        TenantId::from_static("slow-restore"),
        NetworkFunctionKind::smf(),
        [0x35; 32],
    )
    .unwrap();
    let initial = ScopeAuthorityRequest::new(
        scope.clone(),
        [2; 16],
        0,
        ScopeAuthorityOperation::AdmitInitial {
            execution: crate::scope_authority::tests::execution(1),
        },
    )
    .unwrap();
    let admitted = ScopeState::empty(scope.clone())
        .transition(&initial)
        .unwrap();
    let succession = ScopeAuthorityRequest::new(
        scope,
        [4; 16],
        1,
        ScopeAuthorityOperation::SucceedClosed {
            predecessor: admitted.view.stamp().unwrap().clone(),
            execution: crate::scope_authority::tests::execution(2),
            evidence: ScopeClosureEvidence::new(ScopeClosureKind::FinalTermination, [4; 32])
                .unwrap(),
        },
    )
    .unwrap();
    let successor = admitted.transition(&succession).unwrap();
    let stamp = successor.view.stamp().unwrap().clone();
    append_commit_and_apply(
        &mut log,
        &mut machine,
        [
            fixed_initial_membership_entry(),
            authorized(
                1,
                SessionMutationIntent::ActivateScopeProfile(Box::new(ScopeProfileActivation::new(
                    identity(1),
                    fenced_transition_voter_set_digest(identity(1), &fixed_raw_read_members()),
                ))),
            ),
            authorized(
                2,
                SessionMutationIntent::ScopeAuthority(Box::new(ScopeAuthorityCommand {
                    request: initial,
                })),
            ),
            authorized(
                3,
                SessionMutationIntent::ScopeBatch(Box::new(ScopeBatchCommand {
                    request: ScopeBatchRequest::new(
                        admitted.view.stamp().unwrap(),
                        [3; 16],
                        0,
                        (1..=4)
                            .map(|n| crate::scope_batch::tests::create(n, &[]))
                            .collect(),
                        vec![],
                    )
                    .unwrap(),
                })),
            ),
            authorized(
                4,
                SessionMutationIntent::ScopeAuthority(Box::new(ScopeAuthorityCommand {
                    request: succession.clone(),
                })),
            ),
        ],
        "composed scan initial state",
    )
    .await;
    let scheduler_owner = ScopeSchedulerOwner::default();
    let scheduler = scheduler_owner.scheduler();
    let registry = Arc::clone(&machine.core.scope_views);
    let observed = Arc::new(Observed::default());
    let installation = Arc::new(tokio::sync::Mutex::new(()));
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    let mut clients = Vec::new();
    let attempts = if continuous_installs { 6 } else { 16 };
    for _ in 0..5 {
        let port = Port {
            core: machine.core.clone(),
            scheduler: scheduler.clone(),
            stamp: stamp.clone(),
            succession: succession.clone(),
            advance: send.clone(),
            installation: Arc::clone(&installation),
            first_slow_read: AtomicBool::new(true),
            observed: Arc::clone(&observed),
        };
        clients.push(tokio::spawn(async move {
            let client = ScopeScanClient::new(port).with_limits(
                ScopeScanPageLimits::default(),
                ScopeScanRetryPolicy::new(
                    attempts,
                    Duration::from_millis(1),
                    Duration::from_millis(8),
                )
                .unwrap(),
            );
            let mut sink = Sink::default();
            let result = client
                .restore(
                    &mut sink,
                    tokio::time::Instant::now() + std::time::Duration::from_secs(60),
                )
                .await;
            assert!(
                sink.cut.is_none(),
                "no old-cut staging may survive termination"
            );
            (result, sink.discarded)
        }));
    }
    drop(send);
    let mut initial_pages = VecDeque::new();
    for _ in 0..4 {
        initial_pages.push_back(bounded(receive.recv()).await.unwrap());
    }
    bounded(async {
        while registry.metrics().waiting_views != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(registry.metrics().active_views, 4);
    assert_eq!(
        scheduler.snapshot().class(ScopeWorkClass::Normal).running,
        0,
        "the fifth restore may not keep an execution permit while awaiting retention"
    );
    let mut writes = 0u64;
    let mut installs = 0;
    loop {
        let advance = match initial_pages.pop_front() {
            Some(advance) => Some(advance),
            None => bounded(receive.recv()).await,
        };
        let Some(advance) = advance else { break };
        // Keep writing the actual stable-scope checkpoint while each page is
        // outstanding. Its older captured checkpoint remains part of its cut.
        let request = ScopeBatchRequest::new(
            &stamp,
            (0x2000 + u128::from(writes)).to_be_bytes(),
            writes + 1,
            vec![],
            vec![ScopeCounterMutation::new(0, writes, writes + 1).unwrap()],
        )
        .unwrap();
        writes += 1;
        let entry = authorized(
            writes + 4,
            SessionMutationIntent::ScopeBatch(Box::new(ScopeBatchCommand { request })),
        );
        append_and_commit(&mut log, [entry.clone()], "write during composed restore").await;
        let response = machine.apply([entry]).await.unwrap().remove(0);
        let outcome = match response.result {
            Ok(SessionMutationOutcome::ScopeBatch(Ok(outcome))) => outcome,
            Ok(SessionMutationOutcome::ScopeBatch(Err(error))) => {
                panic!("checkpoint write {writes} after {installs} installs refused: {error}")
            }
            other => panic!(
                "checkpoint write {writes} after {installs} installs did not commit: {other:?}"
            ),
        };
        assert_eq!(outcome.revision(), writes + 1);
        assert_eq!(outcome.counters()[0], writes);
        if writes.is_multiple_of(3) && (continuous_installs || writes <= 6) {
            let _installation = installation.lock().await;
            let mut snapshot = machine
                .get_snapshot_builder()
                .await
                .build_snapshot()
                .await
                .unwrap();
            let mut receiving = machine.begin_receiving_snapshot().await.unwrap();
            tokio::io::copy(&mut snapshot.snapshot, &mut receiving)
                .await
                .unwrap();
            bounded(machine.install_snapshot(&snapshot.meta, receiving))
                .await
                .unwrap();
            assert_installed_scope(&machine.core, &stamp, &succession, writes).await;
            installs += 1;
        }
        let _ = advance.send(());
    }
    let mut completed = 0;
    let mut stalled = 0;
    let mut discarded = 0;
    for client in clients {
        let (result, lost) = bounded(client).await.unwrap();
        discarded += lost;
        match result {
            Ok(4) => completed += 1,
            Err(ScopeScanClientError::Stalled(reason)) => {
                assert_eq!(reason.attempts(), attempts);
                assert!(reason.attempts_for(ScopeScanRetryCause::SnapshotInstalled) > 0);
                stalled += 1;
            }
            result => {
                panic!("restore did not complete or return its typed finite stall: {result:?}")
            }
        }
    }
    if continuous_installs {
        assert_eq!(stalled, 5);
    } else {
        assert_eq!(completed, 5);
    }
    assert!(writes >= 6 && installs >= 2);
    assert!(discarded > 0);
    assert!(observed.no_progress.load(Ordering::SeqCst) > 0);
    if !continuous_installs {
        assert!(observed.partial_pages.load(Ordering::SeqCst) > 0);
    }
    assert_eq!(
        (
            registry.metrics().active_views,
            registry.metrics().waiting_views
        ),
        (0, 0)
    );
    assert_eq!(
        scheduler.snapshot().class(ScopeWorkClass::Normal).resident,
        0
    );
    wal.current().unwrap().shutdown().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_scan_native_composed_writes_slow_pages_and_periodic_installs_complete() {
    composed(true, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_scan_sqlite_composed_writes_slow_pages_and_periodic_installs_complete() {
    composed(false, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_scan_native_composed_continuous_installs_stall_within_budget() {
    composed(true, true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scope_scan_sqlite_composed_continuous_installs_stall_within_budget() {
    composed(false, true).await;
}
