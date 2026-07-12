mod tcp_consensus_common;

use async_trait::async_trait;
use opc_persist::{
    AppendEntriesRequest, AppendEntriesResponse, ClusterMembership, ConfigStore, ConsensusClock,
    ConsensusConfigStore, ConsensusOp, ConsensusPeer, InstallSnapshotRequest,
    InstallSnapshotResponse, LogEntry, PersistError, RequestVoteRequest, RequestVoteResponse, Role,
    RollbackTarget, SqliteBackend, StoredConfig, TcpPeer, TimeoutNowRequest, TimeoutNowResponse,
};
use opc_types::TxId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tcp_consensus_common::{
    generate_test_ca_and_identities, make_audit_record, make_commit_record, test_audit_key,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Deserialize)]
struct WireAuthenticatedRequest {
    request: WireRequest,
}

#[derive(Deserialize)]
enum WireRequest {
    RequestVote(RequestVoteRequest),
    AppendEntries(AppendEntriesRequest),
    InstallSnapshot(InstallSnapshotRequest),
    LoadLatest,
    LoadRollback(RollbackTarget),
}

#[derive(Serialize)]
struct WireAuthenticatedResponse {
    response: WireResponse,
}

#[derive(Serialize)]
enum WireResponse {
    RequestVote(Result<RequestVoteResponse, String>),
    AppendEntries(Result<AppendEntriesResponse, String>),
    InstallSnapshot(Result<InstallSnapshotResponse, String>),
    LoadLatest(Result<Option<StoredConfig>, String>),
    LoadRollback(Result<StoredConfig, String>),
}

#[derive(Debug)]
struct ReadQuorumPeer;

#[async_trait]
impl ConsensusPeer for ReadQuorumPeer {
    fn node_id(&self) -> usize {
        0
    }

    async fn request_vote(
        &self,
        _req: RequestVoteRequest,
    ) -> Result<RequestVoteResponse, PersistError> {
        Err(PersistError::io("unexpected replay-test vote"))
    }

    async fn append_entries(
        &self,
        req: AppendEntriesRequest,
    ) -> Result<AppendEntriesResponse, PersistError> {
        Ok(AppendEntriesResponse {
            term: req.term,
            success: true,
        })
    }

    async fn install_snapshot(
        &self,
        _req: InstallSnapshotRequest,
    ) -> Result<InstallSnapshotResponse, PersistError> {
        Err(PersistError::io("unexpected replay-test snapshot"))
    }

    async fn load_latest_consensus_rpc(&self) -> Result<Option<StoredConfig>, PersistError> {
        Err(PersistError::io("unexpected replay-test latest read"))
    }

    async fn load_rollback_consensus_rpc(
        &self,
        _target: RollbackTarget,
    ) -> Result<StoredConfig, PersistError> {
        Err(PersistError::io("unexpected replay-test rollback read"))
    }

    async fn timeout_now(
        &self,
        _req: TimeoutNowRequest,
    ) -> Result<TimeoutNowResponse, PersistError> {
        Err(PersistError::io("unexpected replay-test timeout-now"))
    }
}

async fn read_append_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> AppendEntriesRequest {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await.unwrap();
    let mut body = vec![0u8; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut body).await.unwrap();
    let request: WireAuthenticatedRequest = serde_json::from_slice(&body).unwrap();
    match request.request {
        WireRequest::AppendEntries(request) => request,
        _ => panic!("expected AppendEntries request"),
    }
}

#[tokio::test]
async fn append_entries_response_loss_retries_an_applied_request_successfully() {
    let (_, _, identities) = generate_test_ca_and_identities(&[0, 1]);
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(
        SqliteBackend::open_with_audit_key(
            temp_dir.path().join("append-replay.db"),
            true,
            0,
            test_audit_key(),
        )
        .await
        .unwrap(),
    );
    let follower = Arc::new(
        ConsensusConfigStore::new(
            1,
            Arc::clone(&backend),
            Some(ClusterMembership {
                cluster_id: "append-replay-test".to_string(),
                node_id: 1,
                voting_members: vec![0, 1],
                non_voting_members: vec![],
                old_voting_members: None,
                removed_members: vec![],
                epoch: 1,
            }),
            Some(ConsensusClock {
                election_timeout_min: Duration::from_secs(60),
                election_timeout_max: Duration::from_secs(60),
                heartbeat_interval: Duration::from_secs(60),
                enable_timers: false,
            }),
        )
        .await
        .unwrap(),
    );
    follower
        .set_identity(identities.get(&1).unwrap().clone())
        .await
        .unwrap();
    let acceptor = follower.build_tls_acceptor().await.unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server_follower = Arc::clone(&follower);
    let server = tokio::spawn(async move {
        for attempt in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let request = read_append_request(&mut stream).await;
            let response = server_follower
                .handle_append_entries(request)
                .await
                .map_err(|error| error.to_string());

            if attempt == 0 {
                // The follower completed the request, but the response is lost.
                // TcpPeer must retry the identical request on a new connection.
                drop(stream);
                continue;
            }

            let body = serde_json::to_vec(&WireAuthenticatedResponse {
                response: WireResponse::AppendEntries(response),
            })
            .unwrap();
            stream
                .write_all(&(body.len() as u32).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&body).await.unwrap();
        }
    });

    let peer = TcpPeer::new(1, addr, Duration::from_secs(1));
    peer.set_identity(identities.get(&0).unwrap().clone())
        .await
        .unwrap();
    peer.set_auth(0, "append-replay-test".to_string(), String::new())
        .await
        .unwrap();

    let tx_id = TxId::new();
    let response = peer
        .append_entries(AppendEntriesRequest {
            term: 1,
            leader_id: 0,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![LogEntry {
                index: 1,
                term: 1,
                op: ConsensusOp::AppendCommit {
                    record: make_commit_record(tx_id, 1),
                    audit: vec![make_audit_record(tx_id, 0, "/append-replay")],
                },
            }],
            leader_commit: 1,
        })
        .await
        .unwrap();

    assert!(response.success);
    server.await.unwrap();
    assert_eq!(backend.consensus_get_applied_index().await.unwrap(), 1);
    assert_eq!(
        backend.load_latest().await.unwrap().unwrap().record.tx_id,
        tx_id
    );
}

async fn read_wire_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> WireRequest {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await.unwrap();
    let mut body = vec![0u8; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut body).await.unwrap();
    serde_json::from_slice::<WireAuthenticatedRequest>(&body)
        .unwrap()
        .request
}

async fn write_wire_response(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    response: WireResponse,
) {
    let body = serde_json::to_vec(&WireAuthenticatedResponse { response }).unwrap();
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&body).await.unwrap();
}

#[tokio::test]
async fn replay_safe_rpc_handlers_accept_exact_duplicates_after_response_loss() {
    const LOAD_LATEST: usize = 0;
    const LOAD_ROLLBACK: usize = 1;
    const REQUEST_VOTE: usize = 2;
    const INSTALL_SNAPSHOT: usize = 3;

    let (_, _, identities) = generate_test_ca_and_identities(&[0, 1]);
    let temp_dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(
        SqliteBackend::open_with_audit_key(
            temp_dir.path().join("rpc-replay.db"),
            true,
            0,
            test_audit_key(),
        )
        .await
        .unwrap(),
    );

    let first_tx = TxId::new();
    let first_record = make_commit_record(first_tx, 1);
    let first_audit = vec![make_audit_record(first_tx, 0, "/rpc-replay/first")];
    backend
        .append_commit(first_record.clone(), first_audit.clone())
        .await
        .unwrap();
    let second_tx = TxId::new();
    let mut second_record = make_commit_record(second_tx, 2);
    second_record.parent_tx_id = Some(first_tx);
    backend
        .append_commit(
            second_record,
            vec![make_audit_record(second_tx, 0, "/rpc-replay/second")],
        )
        .await
        .unwrap();

    // Generate a fully authenticated, state-advancing snapshot with the same
    // production code as a leader. This lets the first InstallSnapshot call
    // replace follower state before its response is lost; the retry must then
    // take the already-applied duplicate path without repeating that mutation.
    let snapshot_backend = Arc::new(
        SqliteBackend::open_with_audit_key(
            temp_dir.path().join("rpc-replay-snapshot-source.db"),
            true,
            0,
            test_audit_key(),
        )
        .await
        .unwrap(),
    );
    let snapshot_source = ConsensusConfigStore::new(
        1,
        Arc::clone(&snapshot_backend),
        Some(ClusterMembership {
            cluster_id: "rpc-replay-test".to_string(),
            node_id: 1,
            voting_members: vec![0, 1],
            non_voting_members: vec![],
            old_voting_members: None,
            removed_members: vec![],
            epoch: 1,
        }),
        Some(ConsensusClock {
            enable_timers: false,
            ..ConsensusClock::default()
        }),
    )
    .await
    .unwrap();
    snapshot_backend
        .consensus_append_logs(
            0,
            vec![LogEntry {
                index: 1,
                term: 1,
                op: ConsensusOp::AppendCommit {
                    record: first_record,
                    audit: first_audit,
                },
            }],
        )
        .await
        .unwrap();
    snapshot_backend.consensus_apply_entries(1).await.unwrap();
    snapshot_source.compact_logs(1).await.unwrap();
    let (snapshot_index, snapshot_term, snapshot_data) = snapshot_backend
        .consensus_get_snapshot()
        .await
        .unwrap()
        .unwrap();

    // Node 0 is a voter, so its authenticated identity is authorized to carry
    // vote/leader coordinates. An in-process quorum peer lets node 1 prove
    // read leadership before the response-loss requests are exercised over
    // the real mTLS connection.
    let store = Arc::new(
        ConsensusConfigStore::new(
            1,
            Arc::clone(&backend),
            Some(ClusterMembership {
                cluster_id: "rpc-replay-test".to_string(),
                node_id: 1,
                voting_members: vec![0, 1],
                non_voting_members: vec![],
                old_voting_members: None,
                removed_members: vec![],
                epoch: 1,
            }),
            Some(ConsensusClock {
                enable_timers: false,
                ..ConsensusClock::default()
            }),
        )
        .await
        .unwrap(),
    );
    store
        .set_identity(identities.get(&1).unwrap().clone())
        .await
        .unwrap();
    store.add_peer(0, Arc::new(ReadQuorumPeer)).await;
    store.state.lock().await.role = Role::Leader;
    let acceptor = store.build_tls_acceptor().await.unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server_store = Arc::clone(&store);
    let server = tokio::spawn(async move {
        let mut attempts = [0usize; 4];
        while attempts.iter().any(|attempts| *attempts < 2) {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let (family, response) = match read_wire_request(&mut stream).await {
                WireRequest::LoadLatest => (
                    LOAD_LATEST,
                    WireResponse::LoadLatest(
                        server_store
                            .load_latest_consensus_rpc()
                            .await
                            .map_err(|error| error.to_string()),
                    ),
                ),
                WireRequest::LoadRollback(target) => (
                    LOAD_ROLLBACK,
                    WireResponse::LoadRollback(
                        server_store
                            .load_rollback_consensus_rpc(target)
                            .await
                            .map_err(|error| error.to_string()),
                    ),
                ),
                WireRequest::RequestVote(request) => (
                    REQUEST_VOTE,
                    WireResponse::RequestVote(
                        server_store
                            .request_vote(request)
                            .await
                            .map_err(|error| error.to_string()),
                    ),
                ),
                WireRequest::InstallSnapshot(request) => (
                    INSTALL_SNAPSHOT,
                    WireResponse::InstallSnapshot(
                        server_store
                            .install_snapshot(request)
                            .await
                            .map_err(|error| error.to_string()),
                    ),
                ),
                WireRequest::AppendEntries(_) => panic!("unexpected append RPC"),
            };
            attempts[family] += 1;

            if attempts[family] == 1 {
                // The real handler completed and durably mutated state, but
                // its response disappeared. The transport must replay the
                // exact request, and the handler must accept that duplicate.
                drop(stream);
            } else {
                write_wire_response(&mut stream, response).await;
            }
        }
        attempts
    });

    let peer = TcpPeer::new(1, addr, Duration::from_secs(1));
    peer.set_identity(identities.get(&0).unwrap().clone())
        .await
        .unwrap();
    peer.set_auth(0, "rpc-replay-test".to_string(), String::new())
        .await
        .unwrap();

    let latest = peer.load_latest_consensus_rpc().await.unwrap().unwrap();
    assert_eq!(latest.record.tx_id, second_tx);
    let rollback = peer
        .load_rollback_consensus_rpc(RollbackTarget::ByTxId(first_tx))
        .await
        .unwrap();
    assert_eq!(rollback.record.tx_id, first_tx);

    let vote = peer
        .request_vote(RequestVoteRequest {
            term: 1,
            candidate_id: 0,
            last_log_index: 0,
            last_log_term: 0,
        })
        .await
        .unwrap();
    assert!(vote.vote_granted);

    let snapshot = peer
        .install_snapshot(InstallSnapshotRequest {
            term: 1,
            leader_id: 0,
            last_included_index: snapshot_index,
            last_included_term: snapshot_term,
            data: snapshot_data,
        })
        .await
        .unwrap();
    assert!(snapshot.success);

    let attempts = server.await.unwrap();
    assert_eq!(attempts, [2, 2, 2, 2]);
    assert_eq!(backend.consensus_get_state().await.unwrap(), (1, Some(0)));
    assert_eq!(backend.consensus_get_applied_index().await.unwrap(), 1);
    assert_eq!(
        backend.load_latest().await.unwrap().unwrap().record.tx_id,
        first_tx
    );
    assert_eq!(
        backend.consensus_get_snapshot().await.unwrap().unwrap().0,
        1
    );
    assert_eq!(
        store
            .metrics
            .snapshot_installs
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );
}
