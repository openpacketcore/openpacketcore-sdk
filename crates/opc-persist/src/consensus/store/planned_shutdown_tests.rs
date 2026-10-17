use super::*;
use opc_consensus::engine::raft::AppendEntriesRequest;
use tokio::sync::{Notify, RwLock};

#[tokio::test]
async fn shutdown_completion_releases_owned_handles_before_retained_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let node = ConsensusNodeId::new(1).unwrap();
    let identity = opc_consensus::ConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::new("shutdown-owned-handles").unwrap(),
        opc_consensus::ConsensusConfigurationId::from_bytes([0x45; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let topology =
        ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).unwrap();
    let options = crate::RetainedConfigOptions::new(
        directory.path().join("retained.sqlite"),
        crate::RetainedConfigBinding::new(topology.clone(), [1; 32], [2; 32]).unwrap(),
        crate::RetainedConfigDurability::Ephemeral,
        64 * 1024 * 1024,
        Duration::from_secs(30),
    )
    .unwrap();
    let key = crate::AuditKey::new([0x55; 32]).unwrap();
    let backend = SqliteBackend::provision_config_authority(options.clone(), key.clone())
        .await
        .unwrap();
    let connection = Arc::downgrade(&backend.conn());
    let store = ConsensusConfigStore::open(
        topology,
        backend,
        directory.path().join("snapshots"),
        BTreeMap::new(),
    )
    .await
    .unwrap();
    let owner = Arc::downgrade(&store.inner);
    store.initialize_cluster().await.unwrap();
    store.trigger_snapshot().await.unwrap();
    store.shutdown().await.unwrap();
    drop(store);
    eprintln!(
        "shutdown completion: store_owners={}, connection_owners={}",
        owner.strong_count(),
        connection.strong_count()
    );
    assert_eq!(owner.strong_count(), 0, "owned handoff released its store");
    assert_eq!(
        connection.strong_count(),
        0,
        "engine storage owners joined before completion"
    );
    SqliteBackend::reopen_config_authority(options, key)
        .await
        .expect("no shutdown-owned handle can retain the root after completion");
}

#[derive(Debug)]
struct Peer {
    target: ConsensusNodeId,
    handler: RwLock<Option<Arc<dyn ConsensusRpcHandler>>>,
    hold_entries: AtomicBool,
    appended: Notify,
    release: watch::Sender<bool>,
    lagged: Notify,
}

#[async_trait]
impl ConsensusPeer for Peer {
    fn node_id(&self) -> ConsensusNodeId {
        self.target
    }

    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        let handler = self
            .handler
            .read()
            .await
            .clone()
            .ok_or(ConsensusPeerError::Unavailable)?;
        if request.family == ConsensusRpcFamily::AppendEntries
            && self.hold_entries.load(Ordering::Acquire)
        {
            let rpc: AppendEntriesRequest<ConfigRaftTypeConfig> =
                decode_config_wire(&request.payload).unwrap();
            if !rpc.entries.is_empty() {
                self.appended.notify_one();
                self.release
                    .subscribe()
                    .wait_for(|released| *released)
                    .await
                    .unwrap();
            }
        }
        let transfer = request.family == ConsensusRpcFamily::LeadershipTransfer;
        let response = handler.handle(request.sender, request).await;
        if transfer {
            if let Ok(payload) = response.result.as_ref() {
                let result: Result<(), RaftError<ConsensusNodeId, TransferLeaderError>> =
                    decode_config_wire(payload).unwrap();
                if matches!(
                    result,
                    Err(RaftError::APIError(TransferLeaderError::LogNotApplied))
                ) {
                    self.lagged.notify_one();
                }
            }
        }
        Ok(response)
    }
}

async fn lagging_successor(release_prefix: bool) {
    use PlannedShutdownFallback as Reason;
    let directory = tempfile::tempdir().unwrap();
    let nodes = [1, 2, 3].map(|id| ConsensusNodeId::new(id).unwrap());
    let members = nodes.into_iter().collect::<BTreeSet<_>>();
    let identity = opc_consensus::ConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::new("planned-shutdown-lag").unwrap(),
        opc_consensus::ConsensusConfigurationId::from_bytes([0x64; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let mut paths = BTreeMap::new();
    for source in 0..3 {
        for (target, node) in nodes.iter().copied().enumerate() {
            if source != target {
                paths.insert(
                    (source, target),
                    Arc::new(Peer {
                        target: node,
                        handler: RwLock::new(None),
                        hold_entries: AtomicBool::new(false),
                        appended: Notify::new(),
                        release: watch::channel(false).0,
                        lagged: Notify::new(),
                    }),
                );
            }
        }
    }
    let mut stores = Vec::new();
    for index in 0..3 {
        let backend = SqliteBackend::open_with_audit_key(
            directory.path().join(format!("node-{index}.sqlite")),
            true,
            0,
            crate::AuditKey::new([0x55; 32]).unwrap(),
        )
        .await
        .unwrap();
        let peers = (0..3)
            .filter(|target| *target != index)
            .map(|target| {
                let peer: Arc<dyn ConsensusPeer> = paths[&(index, target)].clone();
                (nodes[target], peer)
            })
            .collect();
        stores.push(
            ConsensusConfigStore::open_with_operation_timeout(
                ConfigConsensusTopology::try_new(identity, nodes[index], members.clone()).unwrap(),
                backend,
                directory.path().join(format!("snapshots-{index}")),
                peers,
                Duration::from_secs(3),
            )
            .await
            .unwrap(),
        );
    }
    for ((_, target), peer) in &paths {
        *peer.handler.write().await = Some(stores[*target].rpc_handler());
    }
    let (one, two, three) = tokio::join!(
        stores[0].initialize_cluster(),
        stores[1].initialize_cluster(),
        stores[2].initialize_cluster()
    );
    one.unwrap();
    two.unwrap();
    three.unwrap();
    for store in &stores {
        store.probe_durable_readiness().await.unwrap();
    }
    // SQLite cancellation compares converted operation deadlines to wall time.
    // Complete real startup/readiness before freezing Tokio for the shutdown
    // scenario so setup cannot consume a deadline while virtual time stands still.
    tokio::time::pause();
    let before = stores[0].status().applied_index.unwrap();
    for target in [1, 2] {
        paths[&(0, target)]
            .hold_entries
            .store(true, Ordering::Release);
    }
    // Enqueue an actual accepted log entry after the ordinary admission/read
    // fence. Its domain rejection is irrelevant: the successor must apply the
    // complete accepted prefix, including entries with a rejected state effect.
    let writer = stores[0].clone();
    let started = tokio::time::Instant::now();
    let accepted = tokio::spawn(async move {
        writer
            .submit_request(
                opc_consensus::ConsensusRequestId::from_bytes([0x31; 16]),
                ConfigMutationIntent::MarkConfirmed {
                    tx_id: opc_types::TxId::new(),
                },
            )
            .await
    });
    tokio::join!(
        paths[&(0, 1)].appended.notified(),
        paths[&(0, 2)].appended.notified()
    );
    let required = stores[0]
        .inner
        .raft
        .metrics()
        .borrow()
        .last_log_index
        .unwrap();
    assert!(required > before);
    let store = stores[0].clone();
    let stopping = tokio::spawn(async move { store.shutdown_with_report().await });
    let target = tokio::select! {
        () = paths[&(0, 1)].lagged.notified() => 1,
        () = paths[&(0, 2)].lagged.notified() => 2,
    };
    assert!(stores[target].status().applied_index.unwrap() < required);
    assert!(!stores[0].status().admitted);
    if release_prefix {
        for target in [1, 2] {
            paths[&(0, target)].release.send_replace(true);
        }
        accepted.await.unwrap().unwrap();
        while stores[target]
            .status()
            .applied_index
            .is_none_or(|applied| applied < required)
        {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_millis(100)).await;
        assert_eq!(
            stopping.await.unwrap().unwrap(),
            PlannedShutdownOutcome::LeaderTransferred {
                successor: nodes[target]
            }
        );
        stores[target].probe_durable_readiness().await.unwrap();
        assert!(stores[target].status().applied_index.unwrap() >= required);
    } else {
        tokio::time::advance(
            planned_shutdown_timeout(Duration::from_secs(3)) + Duration::from_millis(1),
        )
        .await;
        // The fallback must also join the held replication RPCs. Advance to
        // their unchanged heartbeat deadline, still inside the three-second
        // shutdown budget; do not release or apply the held prefix.
        tokio::time::advance(Duration::from_millis(501)).await;
        let report = stopping
            .await
            .unwrap()
            .expect("bounded fallback joins the engine");
        assert_eq!(
            report,
            PlannedShutdownOutcome::Fallback {
                reason: Reason::NoUpToDateVoter
            }
        );
        assert!(started.elapsed() < Duration::from_secs(3));
        // An accepted caller keeps its original completion deadline even
        // after the engine stops. Drive that deadline separately from drain.
        tokio::time::advance(Duration::from_secs(3) - started.elapsed() + Duration::from_millis(1))
            .await;
        assert!(
            matches!(
                accepted.await.unwrap().unwrap_err().kind(),
                crate::PersistErrorKind::OutcomeUnknown
            ),
            "uncommitted accepted work keeps its original ambiguous completion"
        );
        assert_eq!(stores[0].shutdown_with_report().await.unwrap(), report);
    }
    let (one, two, three) = tokio::join!(
        stores[0].shutdown(),
        stores[1].shutdown(),
        stores[2].shutdown()
    );
    one.unwrap();
    two.unwrap();
    three.unwrap();
}

async fn with_wall_clock_watchdog(operation: impl Future<Output = ()>) {
    let (release, held) = std::sync::mpsc::channel::<()>();
    let mut watchdog =
        tokio::task::spawn_blocking(move || held.recv_timeout(Duration::from_secs(30)));
    tokio::select! {
        () = operation => {},
        result = &mut watchdog => panic!("planned shutdown wall-clock watchdog expired: {result:?}"),
    }
    tokio::time::resume();
    drop(release);
    assert!(matches!(
        watchdog.await.unwrap(),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
    ));
}

#[tokio::test]
async fn accepted_prefix_catches_up_before_successor_campaigns() {
    with_wall_clock_watchdog(lagging_successor(true)).await;
}

#[tokio::test]
async fn no_up_to_date_voter_has_a_typed_bounded_fallback() {
    with_wall_clock_watchdog(lagging_successor(false)).await;
}
