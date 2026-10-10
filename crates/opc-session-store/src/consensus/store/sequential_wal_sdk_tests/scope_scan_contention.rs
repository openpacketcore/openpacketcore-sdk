//! Successor restores keep their cut and admission while unrelated scopes write.

use super::scope_authority::Admission;
use super::*;
use crate::scope_authority::tests::{execution, identity};
use crate::scope_authority::*;
use crate::scope_batch::tests::create;
use crate::scope_batch::*;
use crate::scope_scan::{
    ScopeScanClientError, ScopeScanPageLimits, ScopeScanReply, ScopeScanRetryCause,
    ScopeScanRetryPolicy, ScopeScanSink, ScopeScanStore,
};
use std::sync::atomic::{AtomicBool, AtomicU64};

fn boot(generation: u64) -> ScopeExecution {
    let process = u128::from(generation).to_le_bytes();
    let mut key = [0; 32];
    key[..16].copy_from_slice(&process);
    key[16..].copy_from_slice(&process);
    ScopeExecution::new(identity("worker-1"), generation, [1; 16], process, key).unwrap()
}

#[derive(Default)]
struct CountingSink {
    staged: usize,
    pages: usize,
}
#[async_trait::async_trait]
impl ScopeScanSink for CountingSink {
    type Error = ();
    type Output = usize;
    async fn begin(
        &mut self,
        _: &crate::scope_scan::ScopeCut,
        _: &ScopeAuthorityView,
        _: &crate::scope_scan::ScopeScanCheckpoint,
    ) -> Result<(), ()> {
        self.staged = 0;
        Ok(())
    }
    async fn stage(&mut self, reply: &ScopeScanReply) -> Result<(), ()> {
        self.pages += 1;
        self.staged += reply.items().len();
        Ok(())
    }
    async fn finish(&mut self, _: &ScopeScanReply) -> Result<usize, ()> {
        Ok(self.staged)
    }
    fn discard(&mut self, _: &crate::scope_scan::ScopeCut) {
        self.staged = 0;
    }
}

async fn admitted(
    store: &Arc<ConsensusSessionStore>,
    consensus: SessionConsensusIdentity,
    slot: u8,
) -> (
    ScopeAuthorityStore,
    ScopeBatchStore,
    CommittedScopeAuthority,
    ScopeId,
) {
    let scope = ScopeId::new(
        consensus,
        TenantId::from_static("scan-contention"),
        NetworkFunctionKind::smf(),
        [slot; 32],
    )
    .unwrap();
    let authority =
        ScopeAuthorityStore::new(Arc::clone(store), scope.clone(), Arc::new(Admission)).unwrap();
    let initial = authority
        .admit(
            &identity("worker-1"),
            &ScopeAuthorityRequest::new(
                scope.clone(),
                [slot; 16],
                0,
                ScopeAuthorityOperation::AdmitInitial {
                    execution: execution(1),
                },
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let batches = ScopeBatchStore::new(
        Arc::clone(store),
        initial.stamp().namespace().clone(),
        Arc::new(Admission),
    )
    .unwrap();
    (authority, batches, initial, scope)
}

async fn contention(native: bool, writers: usize, rows: usize) -> (Result<usize, String>, u64) {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new_with_mode("scope_scan_contention", native);
    fleet.open().await;
    let store = Arc::new(fleet.stores[0].clone());
    let consensus = fleet.topologies[0].consensus_identity().unwrap();
    let (authority, batches, initial, scope) = admitted(&store, consensus, 0x61).await;
    // Sixty children with one claim each: 120 inventory items.
    for chunk in 0..6u8 {
        batches
            .execute(
                &identity("worker-1"),
                &ScopeBatchRequest::new(
                    initial.stamp(),
                    [0x70 + chunk; 16],
                    u64::from(chunk),
                    (1..=10)
                        .map(|n| {
                            let key = chunk * 10 + n;
                            create(key, &[key])
                        })
                        .collect(),
                    vec![],
                )
                .unwrap(),
            )
            .await
            .unwrap();
    }
    let successor = authority
        .admit(
            &identity("worker-1"),
            &ScopeAuthorityRequest::new(
                scope,
                [0x62; 16],
                1,
                ScopeAuthorityOperation::SucceedClosed {
                    predecessor: initial.stamp().clone(),
                    execution: boot(2),
                    evidence: ScopeClosureEvidence::new(
                        ScopeClosureKind::FinalTermination,
                        [0x62; 32],
                    )
                    .unwrap(),
                },
            )
            .unwrap(),
        )
        .await
        .unwrap();
    // Unrelated scopes keep committing ordinary batches during the restore.
    let stop = Arc::new(AtomicBool::new(false));
    let committed = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::new();
    for writer in 0..writers {
        let (_, other, other_initial, _) = admitted(&store, consensus, 0x80 + writer as u8).await;
        let stop = Arc::clone(&stop);
        let committed = Arc::clone(&committed);
        tasks.push(tokio::spawn(async move {
            let mut sequence = 0u64;
            while !stop.load(Ordering::SeqCst) {
                sequence += 1;
                let request = ScopeBatchRequest::in_lane(
                    other_initial.stamp(),
                    (0x9000_0000u128 + (writer as u128) * 1_000_000 + u128::from(sequence))
                        .to_be_bytes(),
                    0,
                    sequence,
                    vec![],
                    vec![ScopeCounterMutation::new(0, sequence - 1, sequence).unwrap()],
                )
                .unwrap();
                if other.execute(&identity("worker-1"), &request).await.is_ok() {
                    committed.fetch_add(1, Ordering::SeqCst);
                } else {
                    sequence -= 1;
                }
            }
        }));
    }
    let scans = ScopeScanStore::new(
        Arc::clone(&store),
        successor.stamp().namespace().clone(),
        Arc::new(Admission),
    )
    .unwrap();
    let client = scans.client(identity("worker-1"), successor).with_limits(
        ScopeScanPageLimits::new(rows, crate::RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES).unwrap(),
        ScopeScanRetryPolicy::default(),
    );
    let before = committed.load(Ordering::SeqCst);
    let mut sink = CountingSink::default();
    let result = client
        .restore_until(
            &mut sink,
            tokio::time::Instant::now() + Duration::from_secs(40),
        )
        .await;
    stop.store(true, Ordering::SeqCst);
    for task in tasks {
        let _ = task.await;
    }
    let result = match result {
        Ok(count) => Ok(count),
        Err(ScopeScanClientError::Stalled(stalled)) => Err(format!(
            "stalled after {} attempts: unavailable={} ended={} budget={}",
            stalled.attempts(),
            stalled.attempts_for(ScopeScanRetryCause::Unavailable),
            stalled.attempts_for(ScopeScanRetryCause::ViewEnded),
            stalled.attempts_for(ScopeScanRetryCause::WorkBudgetExceeded),
        )),
        Err(other) => Err(format!("{other:?}")),
    };
    let writes = committed.load(Ordering::SeqCst) - before;
    eprintln!("accepted data pages before the result: {}", sink.pages);
    fleet.close().await;
    (result, writes)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn scope_scan_sqlite_restore_under_concurrent_scope_writes() {
    let (result, writes) = contention(false, 4, 1).await;
    eprintln!("sqlite restore under writes: {result:?}, concurrent commits {writes}");
    assert_eq!(result, Ok(120));
    assert!(writes > 0, "restore must overlap real committed writes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn scope_scan_native_restore_under_concurrent_scope_writes() {
    let (result, writes) = contention(true, 4, 1).await;
    eprintln!("native restore under writes: {result:?}, concurrent commits {writes}");
    assert_eq!(result, Ok(120));
    assert!(writes > 0, "restore must overlap real committed writes");
}

// A waiting open keeps its place while another view continues paging.
async fn queued(native: bool) -> String {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new_with_mode("scope_scan_queue", native);
    fleet.scan_limits = Some(
        crate::scope_scan::ScopeScanLimits::new(
            1,
            1,
            512 * 1024 * 1024,
            1024 * 1024 * 1024,
            Duration::from_secs(30),
        )
        .unwrap(),
    );
    fleet.open().await;
    let store = Arc::new(fleet.stores[0].clone());
    let consensus = fleet.topologies[0].consensus_identity().unwrap();
    let (authority, batches, initial, scope) = admitted(&store, consensus, 0x63).await;
    batches
        .execute(
            &identity("worker-1"),
            &ScopeBatchRequest::new(
                initial.stamp(),
                [0x71; 16],
                0,
                (1..=10).map(|n| create(n, &[n])).collect(),
                vec![],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let successor = authority
        .admit(
            &identity("worker-1"),
            &ScopeAuthorityRequest::new(
                scope,
                [0x64; 16],
                1,
                ScopeAuthorityOperation::SucceedClosed {
                    predecessor: initial.stamp().clone(),
                    execution: boot(2),
                    evidence: ScopeClosureEvidence::new(
                        ScopeClosureKind::FinalTermination,
                        [0x64; 32],
                    )
                    .unwrap(),
                },
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let scans = Arc::new(
        ScopeScanStore::new(
            Arc::clone(&store),
            successor.stamp().namespace().clone(),
            Arc::new(Admission),
        )
        .unwrap(),
    );
    // Restore A holds the only view and keeps paging well inside its idle bound.
    let limits =
        ScopeScanPageLimits::new(1, crate::RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES).unwrap();
    let active = scans
        .open_restore_with_limits(&identity("worker-1"), &successor, limits)
        .await
        .unwrap();
    let first = scans
        .page(&identity("worker-1"), &active, active.initial_cursor())
        .await
        .unwrap();
    let pager = {
        let scans = Arc::clone(&scans);
        tokio::spawn(async move {
            let mut cursor = first.continuation().unwrap().clone();
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_secs(6)).await;
                let reply = scans
                    .page(&identity("worker-1"), &active, &cursor)
                    .await
                    .unwrap();
                match reply.continuation() {
                    Some(next) => cursor = next.clone(),
                    None => break,
                }
            }
            active.close().await;
        })
    };
    // Restore B has one recovery attempt: waiting itself must spend none.
    let client = scans.client(identity("worker-1"), successor).with_limits(
        limits,
        ScopeScanRetryPolicy::new(1, Duration::from_millis(25), Duration::from_secs(1)).unwrap(),
    );
    let started = std::time::Instant::now();
    let mut sink = CountingSink::default();
    let result = client
        .restore_until(
            &mut sink,
            tokio::time::Instant::now() + Duration::from_secs(40),
        )
        .await;
    let elapsed = started.elapsed();
    let report = match result {
        Ok(count) => format!("completed {count} after {elapsed:?}"),
        Err(ScopeScanClientError::Stalled(stalled)) => format!(
            "stalled after {elapsed:?}: attempts={} unavailable={}",
            stalled.attempts(),
            stalled.attempts_for(ScopeScanRetryCause::Unavailable),
        ),
        Err(other) => format!("{other:?} after {elapsed:?}"),
    };
    let _ = pager.await;
    fleet.close().await;
    report
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn scope_scan_sqlite_queued_restore_waits_while_another_view_pages() {
    let report = queued(false).await;
    eprintln!("queued restore: {report}");
    assert!(report.starts_with("completed 20 "), "{report}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn scope_scan_native_queued_restore_waits_while_another_view_pages() {
    let report = queued(true).await;
    assert!(report.starts_with("completed 20 "), "{report}");
}
