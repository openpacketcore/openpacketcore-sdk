use super::*;
use opc_session_store::{ReplicationRecoveryBoundary, ReplicationReplayPolicy, ReplicationTxId};

fn entry(sequence: u64, recovered: bool) -> ReplicationEntry {
    let mut replay_policy = ReplicationReplayPolicy::preserve();
    if recovered {
        replay_policy.async_fence_floor = 100;
        if sequence == 101 {
            replay_policy.recovery = ReplicationRecoveryBoundary::Recover {
                previous_sequence: 1,
            };
        }
    }
    ReplicationEntry {
        sequence,
        tx_id: ReplicationTxId::from_request_bytes(u128::from(sequence).to_be_bytes()),
        timestamp: Timestamp::now_utc(),
        op: ReplicationOp::Batch { ops: Vec::new() },
        replay_policy,
    }
}

async fn recovery_watch(cursor: u64, live: bool) {
    let mtls = mtls_configs();
    let backend = FakeSessionBackend::new();
    backend.replicate_entry(entry(1, false)).await.unwrap();
    if !live {
        backend.replicate_entry(entry(101, true)).await.unwrap();
    }
    let (addr, backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
    let remote = remote_backend(&mtls, 1, 2, addr, Some(Duration::from_secs(2)));
    let mut watch = remote.watch(cursor).await.unwrap();
    if live {
        backend.replicate_entry(entry(101, true)).await.unwrap();
    }
    backend.replicate_entry(entry(102, true)).await.unwrap();
    let mut actual = Vec::new();
    for _ in 0..2 {
        match tokio::time::timeout(Duration::from_secs(3), watch.next()).await {
            Ok(Some(Ok(entry))) => actual.push(Ok(entry.sequence)),
            Ok(Some(Err(error))) => {
                actual.push(Err(error));
                break;
            }
            other => panic!("watch must deliver committed recovery and successor: {other:?}"),
        }
    }
    drop(watch);
    handle.abort_and_wait().await;
    assert_eq!(actual, vec![Ok(101), Ok(102)]);
}

#[tokio::test]
async fn round6_network_watch_resumes_at_recovery_row() {
    recovery_watch(101, false).await;
}
#[tokio::test]
async fn round6_network_watch_delivers_live_recovery_jump() {
    recovery_watch(2, true).await;
}
#[tokio::test]
async fn round6_network_watch_waits_for_its_recovery_cursor() {
    recovery_watch(101, true).await;
}
