//! Exact audited recovery after real response loss, capacity rejection and leader loss.

use super::*;

fn authority(database: &Path) -> ([i64; 4], [u8; 32], i64) {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only audited authority observation");
    let mac: Vec<u8> = connection
        .query_row(
            "SELECT state_hmac FROM config_raft_management_audit WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("retained authenticated management ledger");
    let proof_count = connection
        .query_row(
            "SELECT COUNT(*) FROM config_raft_capacity_records",
            [],
            |row| row.get(0),
        )
        .expect("retained capacity proof count");
    (
        effect_counts(database),
        mac.try_into()
            .unwrap_or_else(|_| panic!("fixed ledger authentication length")),
        proof_count,
    )
}

async fn lookup(
    store: &ConsensusConfigStore,
    handle: &AuditOperationHandle,
    principal: &str,
    version: u64,
) {
    let receipt = store
        .lookup_audit_operation(handle, caller(principal))
        .await
        .expect("authorized exact read-only audited lookup")
        .expect("original retained audited receipt");
    assert_eq!(receipt.state(), AuditOperationState::Committed { version });
}

native_case!(
    config_capacity_957_joint_audited_ambiguity_capacity_leader_loss_and_reopen,
    {
        let directory = disk_fixture();
        let pki = Pki::new();
        let manifest = manifest();
        let addresses = [0, 1, 2].map(|_| Arc::new(RwLock::new(None)));
        let faults = [0, 1, 2].map(|_| Arc::new(Fault::default()));
        let databases = [0, 1, 2].map(|index| directory.join(format!("config-{index}.sqlite")));
        let profile = ConfigCapacityProfile::BoundedV1;
        let stores = open_members(
            &directory, &manifest, &pki, &addresses, &faults, false, profile,
        )
        .await;
        let (mut servers, released) = snapshot::listen(&stores, &pki, &manifest, &addresses).await;
        snapshot::ready(&stores).await;
        let leader_id = stores[0]
            .status()
            .leader_id
            .expect("audited original leader");
        let leader = stores
            .iter()
            .position(|s| s.status().node_id == leader_id)
            .expect("leader member");
        let follower = (leader + 1) % 3;
        let principal = principal(true);
        stores[leader]
            .initialize_audit_authority(
                &privacy(),
                AuditLedgerLimits::new(12, 4).expect("original ledger limits"),
            )
            .await
            .expect("original replicated audited authority");

        let (control, control_aad, control_plaintext) =
            input(&stores[leader], 1, None, &principal, 0).await;
        let control_record = control.record().clone();
        let control = stores[leader]
            .prepare_audited_commit(
                &privacy(),
                &event(1, &principal),
                control,
                Duration::from_secs(60),
            )
            .expect("prepare acknowledged joint audited control");
        let control_bytes = control
            .handle()
            .encode()
            .expect("retain exact control handle before intent");
        let control_handle =
            AuditOperationHandle::decode(&control_bytes).expect("original control handle");
        let AuditAdmission::Applied(admission) = stores[leader]
            .admit_audit_operation_local(&control_handle, caller(&principal))
            .await
        else {
            panic!("joint audited control intent must be acknowledged");
        };
        assert_eq!(admission.state(), AuditOperationState::Intent);
        let AuditAdmission::Applied(acknowledged) = stores[leader]
            .submit_audited_mutation_local(&control, &admission, caller(&principal))
            .await
        else {
            panic!("joint audited control commit must be acknowledged");
        };
        assert_eq!(
            acknowledged.state(),
            AuditOperationState::Committed { version: 1 }
        );
        drop(control);
        for store in &stores {
            let value = store
                .load_latest()
                .await
                .expect("control quorum read")
                .expect("control head");
            assert_readback(&value, &control_record, &control_aad, &control_plaintext);
            lookup(store, &control_handle, &principal, 1).await;
        }
        drop((control_aad, control_plaintext));

        let (successor, aad, plaintext) = input(
            &stores[follower],
            2,
            Some(control_record.tx_id),
            &principal,
            0,
        )
        .await;
        let expected = successor.record().clone();
        let before = authority(&databases[follower]);
        let prepared = stores[follower]
            .prepare_audited_commit(
                &privacy(),
                &event(2, &principal),
                successor,
                Duration::from_secs(60),
            )
            .expect("prepare joint audited successor exactly once");
        let original_bytes = prepared
            .handle()
            .encode()
            .expect("retain original successor handle before intent");
        let handle =
            AuditOperationHandle::decode(&original_bytes).expect("original successor handle");
        assert!(
            authority(&databases[follower]) == before,
            "preparation has no retained effects"
        );
        let AuditAdmission::Applied(admitted) = stores[follower]
            .admit_audit_operation(&handle, caller(&principal))
            .await
        else {
            panic!("original audited successor intent must be acknowledged before effect");
        };
        assert_eq!(admitted.state(), AuditOperationState::Intent);
        let before_forwards = faults[follower].actual_forwards.load(Ordering::SeqCst);
        let (observed, observation) = tokio::sync::oneshot::channel();
        let (reserved, reservation) = tokio::sync::oneshot::channel();
        *faults[follower]
            .response_loss_gate
            .lock()
            .expect("install exact effect loss gate") = Some(ResponseLossGate {
            observed,
            reserved: reservation,
        });
        faults[follower]
            .allow_capacity_rejection
            .store(true, Ordering::SeqCst);
        faults[follower].armed.store(true, Ordering::SeqCst);
        let deadline = tokio::time::Instant::now() + DURABLE_CONSENSUS_OPERATION_TIMEOUT;
        let (result, (reservations, committed_authority)) = tokio::join!(
            stores[follower].submit_audited_mutation(&prepared, &admitted, caller(&principal)),
            async {
                tokio::time::timeout_at(deadline, observation)
                    .await
                    .expect("effect response inside original operation deadline")
                    .expect("actual authenticated Applied response");
                let reservations = (0..8)
                    .map(|_| {
                        stores[leader]
                            .try_reserve_config_preparation()
                            .expect("real destination preparation slot")
                            .expect("bounded destination reservation")
                    })
                    .collect::<Vec<_>>();
                assert!(stores[leader].try_reserve_config_preparation().is_err());
                let before = authority(&databases[leader]);
                reserved
                    .send(())
                    .expect("release lost response after actual saturation");
                (reservations, before)
            }
        );
        let AuditAdmission::Unknown(unknown) = result else {
            panic!("CONFIG_CAPACITY_AUDITED_AMBIGUITY_RED: later capacity rejection cannot settle the lost effect");
        };
        assert!(
            unknown == handle,
            "uncertainty preserves the original authenticated operation"
        );
        assert_eq!(faults[follower].lost_responses.load(Ordering::SeqCst), 1);
        assert_eq!(
            faults[follower].resource_rejections.load(Ordering::SeqCst),
            1
        );
        assert_eq!(
            faults[follower].actual_forwards.load(Ordering::SeqCst) - before_forwards,
            2
        );
        assert!(authority(&databases[leader]) == committed_authority);
        assert!(stores[leader].try_reserve_config_preparation().is_err());
        lookup(&stores[follower], &handle, &principal, 2).await;
        lookup(&stores[follower], &control_handle, &principal, 1).await;
        assert!(
            authority(&databases[leader]) == committed_authority,
            "full admission still permits read-only recovery"
        );
        drop(reservations);
        let reservations = (0..8)
            .map(|_| {
                stores[leader]
                    .try_reserve_config_preparation()
                    .expect("all destination slots released")
                    .expect("bounded released slot")
            })
            .collect::<Vec<_>>();
        assert!(stores[leader].try_reserve_config_preparation().is_err());
        drop((reservations, prepared));
        for store in &stores {
            lookup(store, &handle, &principal, 2).await;
            let value = store
                .load_latest()
                .await
                .expect("committed audited quorum read")
                .expect("successor head");
            assert_readback(&value, &expected, &aad, &plaintext);
        }

        // Orderly leader loss; process-crash qualification is a separate acceptance row.
        election::begin(&faults);
        let original_term = stores[leader].status().term;
        servers[leader]
            .take()
            .expect("original leader listener")
            .abort_and_wait()
            .await;
        stores[leader]
            .shutdown()
            .await
            .expect("stop original audited leader");
        let live = (0..3).filter(|index| *index != leader).collect::<Vec<_>>();
        let convergence_deadline =
            tokio::time::Instant::now() + CONFIG_CAPACITY_CLUSTER_RECOVERY_TIMEOUT;
        let readiness = tokio::time::timeout_at(convergence_deadline, async {
            for _round in 1..=3 {
                let (one, two) = tokio::join!(
                    stores[live[0]].probe_durable_readiness(),
                    stores[live[1]].probe_durable_readiness(),
                );
                if one.is_ok() && two.is_ok() {
                    assert!(tokio::time::Instant::now() <= convergence_deadline);
                    return;
                }
                report_failover_observation(&stores, &faults, &live, leader_id, original_term);
                for result in [&one, &two] {
                    if let Err(error) = result {
                        assert!(matches!(error.kind(), PersistErrorKind::Unavailable));
                    }
                }
            }
            panic!("surviving audited voters did not become ready in three read-only rounds");
        })
        .await;
        if readiness.is_err() {
            report_failover_observation(&stores, &faults, &live, leader_id, original_term);
        }
        election::report(&faults);
        readiness.expect("audited failover inside unchanged convergence deadline");
        assert!(
            stores[follower]
                .status()
                .leader_id
                .expect("audited successor leader")
                != leader_id
        );
        let before = live
            .iter()
            .map(|index| authority(&databases[*index]))
            .collect::<Vec<_>>();
        let forwards = faults
            .each_ref()
            .map(|fault| fault.actual_forwards.load(Ordering::SeqCst));
        let reads = faults
            .each_ref()
            .map(|fault| fault.read_barriers.load(Ordering::SeqCst));
        let wrong_caller = AuditCaller::project(&privacy(), "test", "spiffe://test.invalid/other")
            .expect("synthetic distinct authorized identity");
        assert!(matches!(
            stores[follower]
                .lookup_audit_operation(&handle, wrong_caller)
                .await,
            Err(AuditAuthorityError::BindingMismatch)
        ));
        assert_eq!(
            faults
                .each_ref()
                .map(|fault| fault.read_barriers.load(Ordering::SeqCst)),
            reads
        );
        for index in &live {
            lookup(&stores[*index], &control_handle, &principal, 1).await;
            lookup(&stores[*index], &handle, &principal, 2).await;
            let value = stores[*index]
                .load_latest()
                .await
                .expect("audited successor quorum read")
                .expect("successor head");
            assert_readback(&value, &expected, &aad, &plaintext);
        }
        assert!(
        live.iter()
            .map(|index| authority(&databases[*index]))
            .collect::<Vec<_>>()
            == before,
        "audited recovery leaves configuration, audit, outcomes, native log and proofs unchanged"
    );
        assert_eq!(
            faults
                .each_ref()
                .map(|fault| fault.actual_forwards.load(Ordering::SeqCst)),
            forwards
        );
        assert_eq!(
            acknowledged.state(),
            AuditOperationState::Committed { version: 1 }
        );
        snapshot::stop(stores, servers, released, &addresses).await;
        let retained = databases.each_ref().map(|path| {
            let (counts, ledger, proofs) = authority(path);
            ([counts[0], counts[1], counts[3]], ledger, proofs)
        });
        let stores = open_members(
            &directory, &manifest, &pki, &addresses, &faults, true, profile,
        )
        .await;
        assert!(
            databases.each_ref().map(|path| {
                let (counts, ledger, proofs) = authority(path);
                ([counts[0], counts[1], counts[3]], ledger, proofs)
            }) == retained,
            "original audited authority restores before transport catch-up"
        );
        let handle =
            AuditOperationHandle::decode(&original_bytes).expect("same retained successor handle");
        let control_handle =
            AuditOperationHandle::decode(&control_bytes).expect("same retained control handle");
        let (servers, released) = snapshot::listen(&stores, &pki, &manifest, &addresses).await;
        snapshot::ready(&stores).await;
        let before = databases.each_ref().map(|path| authority(path));
        let forwards = faults
            .each_ref()
            .map(|fault| fault.actual_forwards.load(Ordering::SeqCst));
        for store in &stores {
            lookup(store, &handle, &principal, 2).await;
            lookup(store, &control_handle, &principal, 1).await;
            let value = store
                .load_latest()
                .await
                .expect("reopened audited quorum read")
                .expect("retained head");
            assert_readback(&value, &expected, &aad, &plaintext);
        }
        assert!(databases.each_ref().map(|path| authority(path)) == before);
        assert_eq!(
            faults
                .each_ref()
                .map(|fault| fault.actual_forwards.load(Ordering::SeqCst)),
            forwards
        );
        for path in &databases {
            let (counts, _, proofs) = authority(path);
            assert_eq!(counts[0], 2);
            assert_eq!(counts[1], (2 * AUDIT_RECORDS) as i64);
            assert_eq!(proofs, 2);
        }
        snapshot::stop(stores, servers, released, &addresses).await;
        println!("CONFIG_CAPACITY_AUDITED_RECOVERY logical=1572864 replay=65536 aad=65536 key_id=512 response_lost=true actual_capacity_rejection=true ambiguity_preserved=true leader_lost=true native_wal=true mtls=true original_paths=true original_handles=true resubmitted=false");
    }
);
