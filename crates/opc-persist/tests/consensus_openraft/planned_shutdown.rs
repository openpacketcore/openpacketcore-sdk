use super::*;

/// Keep disk work off the protocol clock. Even the earliest ordinary election
/// needs the unchanged eight-second lease plus five-second election timeout.
/// A planned stop must hand off while its authenticated transport is still up.
#[tokio::test(start_paused = true)]
async fn planned_leader_stop_preserves_write_stream_within_operation_budget() {
    scripted_election::schedule::with_frozen_time(async {
        let budget = DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout();
        let cluster = ThreeNodeCluster::build_with_operation_timeout(
            [[0x55; 32]; 3],
            FixtureStorage::Legacy,
            None,
            None,
            Duration::ZERO,
            budget,
        )
        .await;
        let (one, two, three) = tokio::join!(
            cluster.stores[0].initialize_cluster(),
            cluster.stores[1].initialize_cluster(),
            cluster.stores[2].initialize_cluster(),
        );
        one.unwrap();
        two.unwrap();
        three.unwrap();
        cluster.wait_ready().await;
        let leader = cluster.leader();
        let survivors: Vec<_> = (0..3).filter(|index| *index != leader).collect();
        let first = TxId::new();
        cluster.stores[leader]
            .append_attested_commit(attested(commit(first, None, 1, 10), audit(first)))
            .await
            .unwrap();

        // The second write is accepted and replicated, but its original client
        // response is in flight when shutdown begins. Retain its ID for recovery.
        let second = TxId::new();
        let request = ConfigConsensusRequestId::from_bytes([0x81; 16]);
        let second_record = commit(second, Some(first), 2, 11);
        let second_audit = audit(second);
        let accepted = attested(second_record.clone(), second_audit.clone());
        let path = &cluster.paths[&(survivors[0], leader)];
        path.pause_forward_response.store(true, Ordering::SeqCst);
        let caller = cluster.stores[survivors[0]].clone();
        let in_flight = tokio::spawn(async move {
            caller
                .append_commit_idempotent(
                    request,
                    accepted,
                )
                .await
        });
        path.forward_response_ready.notified().await;
        let (lagged, mut lag) = tokio::sync::mpsc::unbounded_channel();
        for ((source, _), path) in &cluster.paths {
            if *source == leader {
                *path.transfer_lag.lock().unwrap() = Some(lagged.clone());
            }
        }
        let stopped_at = tokio::time::Instant::now();
        let shutdown = cluster.stores[leader].shutdown();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                result = &mut shutdown => {
                    result.unwrap();
                    break;
                }
                Some((node, required)) = lag.recv() => {
                    // A real LogNotApplied response starts the store's retry
                    // wait. Let disk/apply work finish without consuming its
                    // budget, then advance only the bounded control retry.
                    let target = cluster.stores.iter().find(|store| store.status().node_id == node).unwrap();
                    while target.status().applied_index.is_none_or(|applied| applied < required) {
                        tokio::task::yield_now().await;
                    }
                    tokio::time::advance(Duration::from_millis(100)).await;
                }
            }
        }
        assert!(stopped_at.elapsed() < budget, "handoff preserves the original operation budget");
        cluster.isolate(leader);

        let mut parent = second;
        let mut version = 3;
        let mut outages = Vec::new();
        // Exercise every surviving local authority route once per second,
        // through an instant strictly beyond the complete operation budget.
        // A failed proposal is never silently retried as a different request.
        for tick in 0..=11 {
            if tick > 0 {
                tokio::time::advance(Duration::from_secs(1)).await;
            }
            let tx = TxId::new();
            let record = commit(tx, Some(parent), version, 12);
            let audit = audit(tx);
            let mut committed = false;
            for survivor in &survivors {
                let result = cluster.stores[*survivor]
                    .append_attested_commit_local(attested(
                        record.clone(),
                        audit.clone(),
                    ))
                    .await;
                if result.is_ok() {
                    committed = true;
                    parent = tx;
                    version += 1;
                    break;
                }
            }
            if !committed {
                outages.push(stopped_at.elapsed());
            }
        }
        let error = in_flight.await.unwrap().expect_err("lost response stays ambiguous");
        assert!(matches!(error.kind(), PersistErrorKind::OutcomeUnknown));
        eprintln!(
            "planned stop: in_flight={:?}, operation_budget={budget:?}, unavailable_at={outages:?}",
            error.kind(),
        );
        assert!(
            outages.is_empty(),
            "planned shutdown returned without a writable successor; outages={outages:?}, budget={budget:?}"
        );
        cluster.stores[survivors[0]]
            .append_commit_idempotent(
                request,
                attested(second_record, second_audit),
            )
            .await
            .expect("same-ID recovery finds the accepted write after handoff");
        cluster.shutdown().await;
    })
    .await;
}
