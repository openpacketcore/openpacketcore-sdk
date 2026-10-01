//! Actual at-limit confirmed and rollback successors on both native routes.

use super::*;
use opc_persist::ConfirmedCommitResolution;

fn history_state(database: &Path) -> Vec<(u64, bool, bool)> {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only resolution state");
    let mut statement = connection.prepare(
        "SELECT version, confirmed_deadline IS NOT NULL, confirmed_at IS NOT NULL FROM config_history ORDER BY version",
    ).expect("bounded resolution state query");
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("resolution state rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("complete resolution state");
    let proofs: usize = connection
        .query_row(
            "SELECT COUNT(*) FROM config_raft_capacity_records",
            [],
            |row| row.get(0),
        )
        .expect("atomic retained capacity evidence");
    assert_eq!(
        proofs,
        rows.len(),
        "each retained record keeps exactly one proof"
    );
    rows
}

async fn submit(
    store: &ConsensusConfigStore,
    value: AttestedConfigCommit,
    principal: &str,
    audited: bool,
    local: bool,
    version: u64,
) -> Recovery {
    if audited {
        let prepared = store
            .prepare_audited_commit(
                &privacy(),
                &event(version, principal),
                value,
                Duration::from_secs(60),
            )
            .expect("at-limit audited successor preparation");
        let handle = prepared.handle().clone();
        let admission = if local {
            store
                .admit_audit_operation_local(&handle, caller(principal))
                .await
        } else {
            store
                .admit_audit_operation(&handle, caller(principal))
                .await
        };
        let AuditAdmission::Applied(receipt) = admission else {
            panic!("successor intent needs an authoritative receipt");
        };
        assert_eq!(receipt.state(), AuditOperationState::Intent);
        let result = if local {
            store
                .submit_audited_mutation_local(&prepared, &receipt, caller(principal))
                .await
        } else {
            store
                .submit_audited_mutation(&prepared, &receipt, caller(principal))
                .await
        };
        let AuditAdmission::Applied(receipt) = result else {
            panic!("successor acknowledgement must prove durable commit");
        };
        assert_eq!(receipt.state(), AuditOperationState::Committed { version });
        Recovery::Audited(Box::new(handle))
    } else {
        let prepared = store
            .prepare_recoverable_commit(
                ConfigConsensusRequestId::from_bytes([0xC0 + u8::try_from(version).unwrap(); 16]),
                value,
                principal,
            )
            .expect("at-limit ordinary successor preparation");
        let handle = prepared.recovery_handle().clone();
        if local {
            store.append_prepared_commit_local(prepared).await
        } else {
            store.append_prepared_commit(prepared).await
        }
        .expect("at-limit ordinary successor durable acknowledgement");
        Recovery::Ordinary(handle)
    }
}

async fn run(audited: bool, confirm: bool, local: bool) {
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
    let (servers, released) = snapshot::listen(&stores, &pki, &manifest, &addresses).await;
    snapshot::ready(&stores).await;
    let leader_id = stores[0].status().leader_id.expect("resolution leader");
    let leader = stores
        .iter()
        .position(|store| store.status().node_id == leader_id)
        .expect("resolution leader membership");
    let source = if local { leader } else { (leader + 1) % 3 };
    let principal = principal(audited);
    if audited {
        stores[leader]
            .initialize_audit_authority(
                &privacy(),
                AuditLedgerLimits::new(12, 4).expect("original ledger limit"),
            )
            .await
            .expect("real successor audit authority");
    }
    let (pending, pending_aad, pending_plaintext) =
        input_mode(&stores[leader], 1, None, &principal, 0, CommitMode::Pending).await;
    let pending_record = pending.record().clone();
    let pending_handle = submit(&stores[leader], pending, &principal, audited, true, 1).await;
    for store in &stores {
        let value = store
            .load_latest()
            .await
            .expect("pending quorum read")
            .expect("pending head");
        assert_readback(&value, &pending_record, &pending_aad, &pending_plaintext);
    }
    assert_eq!(
        databases.each_ref().map(|path| history_state(path)),
        std::array::from_fn::<_, 3, _>(|_| vec![(1, true, false)])
    );

    let resolution = if confirm {
        ConfirmedCommitResolution::Confirm {
            pending_tx_id: pending_record.tx_id,
        }
    } else {
        ConfirmedCommitResolution::Rollback {
            pending_tx_id: pending_record.tx_id,
        }
    };
    let (over, _, _) = input_mode(
        &stores[source],
        2,
        Some(pending_record.tx_id),
        &principal,
        1,
        CommitMode::Resolve(resolution),
    )
    .await;
    let effects_before = databases.each_ref().map(|path| effect_counts(path));
    let state_before = databases.each_ref().map(|path| history_state(path));
    let forwards = faults[source].actual_forwards.load(Ordering::SeqCst);
    if audited {
        assert!(matches!(
            stores[source].prepare_audited_commit(
                &privacy(),
                &event(2, &principal),
                over,
                Duration::from_secs(60),
            ),
            Err(AuditAuthorityError::InvalidInput)
        ));
    } else {
        let error = stores[source]
            .prepare_recoverable_commit(
                ConfigConsensusRequestId::from_bytes([0xC9; 16]),
                over,
                &principal,
            )
            .expect_err("one-over resolution path must reject before proposal");
        assert!(matches!(
            error.kind(),
            PersistErrorKind::ConstraintViolation(_)
        ));
    }
    assert_eq!(
        databases.each_ref().map(|path| effect_counts(path)),
        effects_before
    );
    assert_eq!(
        databases.each_ref().map(|path| history_state(path)),
        state_before
    );
    assert_eq!(
        faults[source].actual_forwards.load(Ordering::SeqCst),
        forwards
    );
    let reservations = (0..8)
        .map(|_| {
            stores[source]
                .try_reserve_config_preparation()
                .expect("negative releases its destination reservation")
                .expect("bounded slot")
        })
        .collect::<Vec<_>>();
    assert!(stores[source].try_reserve_config_preparation().is_err());
    drop(reservations);

    let (successor, aad, plaintext) = input_mode(
        &stores[source],
        2,
        Some(pending_record.tx_id),
        &principal,
        0,
        CommitMode::Resolve(resolution),
    )
    .await;
    let expected = successor.record().clone();
    let handle = submit(&stores[source], successor, &principal, audited, local, 2).await;
    assert_eq!(
        faults[source].actual_forwards.load(Ordering::SeqCst) - forwards,
        if local {
            0
        } else if audited {
            2
        } else {
            1
        }
    );
    for store in &stores {
        let value = store
            .load_latest()
            .await
            .expect("resolved quorum read")
            .expect("successor head");
        assert_readback(&value, &expected, &aad, &plaintext);
        recover(store, &pending_handle, &principal, 1).await;
        recover(store, &handle, &principal, 2).await;
    }
    let expected_state = vec![(1, true, confirm), (2, false, false)];
    for path in &databases {
        assert_eq!(history_state(path), expected_state);
        let counts = effect_counts(path);
        assert_eq!(counts[0], 2);
        assert_eq!(counts[1], (2 * AUDIT_RECORDS) as i64);
    }
    snapshot::stop(stores, servers, released, &addresses).await;
    let authority_before = databases.each_ref().map(|path| {
        let counts = effect_counts(path);
        [counts[0], counts[1], counts[3]]
    });
    let stores = open_members(
        &directory, &manifest, &pki, &addresses, &faults, true, profile,
    )
    .await;
    assert_eq!(
        databases.each_ref().map(|path| {
            let counts = effect_counts(path);
            [counts[0], counts[1], counts[3]]
        }),
        authority_before,
        "retained authority is correct before network catch-up"
    );
    for path in &databases {
        assert_eq!(history_state(path), expected_state);
    }
    let (servers, released) = snapshot::listen(&stores, &pki, &manifest, &addresses).await;
    snapshot::ready(&stores).await;
    let effects_before = databases.each_ref().map(|path| effect_counts(path));
    let forwards_before = faults
        .each_ref()
        .map(|fault| fault.actual_forwards.load(Ordering::SeqCst));
    for store in &stores {
        recover(store, &pending_handle, &principal, 1).await;
        recover(store, &handle, &principal, 2).await;
        let value = store
            .load_latest()
            .await
            .expect("retained resolved read")
            .expect("retained successor");
        assert_readback(&value, &expected, &aad, &plaintext);
    }
    assert_eq!(
        databases.each_ref().map(|path| effect_counts(path)),
        effects_before
    );
    assert_eq!(
        faults
            .each_ref()
            .map(|fault| fault.actual_forwards.load(Ordering::SeqCst)),
        forwards_before
    );
    for path in &databases {
        assert_eq!(history_state(path), expected_state);
    }
    snapshot::stop(stores, servers, released, &addresses).await;
    println!("CONFIG_CAPACITY_RESOLUTION audited={audited} confirm={confirm} local={local} logical=1572864 replay=65536 aad=65536 key_id=512 atomic=true path_one_over=rejected original_paths=true original_handles=true resubmitted=false");
}

macro_rules! cases {
    ($name:ident, $audited:expr, $confirm:expr, $local:expr) => {
        native_case!($name, {
            run($audited, $confirm, $local).await;
        });
    };
}

cases!(
    config_capacity_957_ordinary_confirm_local,
    false,
    true,
    true
);
cases!(
    config_capacity_957_ordinary_confirm_forwarded,
    false,
    true,
    false
);
cases!(
    config_capacity_957_ordinary_rollback_local,
    false,
    false,
    true
);
cases!(
    config_capacity_957_ordinary_rollback_forwarded,
    false,
    false,
    false
);
cases!(config_capacity_957_audited_confirm_local, true, true, true);
cases!(
    config_capacity_957_audited_confirm_forwarded,
    true,
    true,
    false
);
cases!(
    config_capacity_957_audited_rollback_local,
    true,
    false,
    true
);
cases!(
    config_capacity_957_audited_rollback_forwarded,
    true,
    false,
    false
);
