//! Seeded parity at every delivered entry, including recovery-local operations.
use super::*;

const SEEDS: [u64; 4] = [
    0x9E3779B97F4A7C15,
    0xD1B54A32D192ED03,
    0x94D049BB133111EB,
    0x8538EA919F4A7C15,
];
fn draw(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

async fn local_recovery_probe(
    native: &NativeStorage,
    journal: &[crate::ReplicationEntry],
    old: &LeaseGuard,
    clock: Arc<ReplayClock>,
    now: Timestamp,
) {
    let replica = FakeSessionBackend::new().with_clock(clock);
    replica
        .rebuild_replication_state(journal.to_vec())
        .await
        .unwrap();
    let before = crate::fake::tests::backend_data_snapshot(&replica).await;
    for operation in 0..2 {
        let mut source = native.clone();
        let intent = if operation == 0 {
            SessionMutationIntent::RenewLease {
                lease: old.clone(),
                ttl: Duration::from_secs(60),
            }
        } else {
            SessionMutationIntent::ReleaseLease(old.clone())
        };
        let mut command = key_retention_tests::command_at(
            source.business.applied().unwrap().index + 1,
            intent,
            now,
        );
        command.log_id.leader_id = source.business.applied().unwrap().leader_id;
        let result = apply(&mut source, &[command]);
        assert_eq!(result.responses[0].result, Err(StoreError::StaleFence));
        let result = if operation == 0 {
            replica
                .renew(old, Duration::from_secs(60))
                .await
                .map(|_| ())
        } else {
            replica.release(old.clone()).await
        };
        assert_eq!(result, Err(LeaseError::StaleFence));
        assert_eq!(
            crate::fake::tests::backend_data_snapshot(&replica).await,
            before
        );
    }
    let mut source = native.clone();
    let owner = crate::OwnerId::new("seeded-successor").unwrap();
    let mut command = key_retention_tests::command_at(
        source.business.applied().unwrap().index + 1,
        SessionMutationIntent::AcquireLease {
            key: old.key().clone(),
            owner: owner.clone(),
            ttl: Duration::from_secs(60),
        },
        now,
    );
    command.log_id.leader_id = source.business.applied().unwrap().leader_id;
    let result = apply(&mut source, &[command]);
    let Ok(SessionMutationOutcome::Lease(expected)) = &result.responses[0].result else {
        panic!("source successor admission")
    };
    assert_eq!(
        replica
            .acquire(old.key(), owner, Duration::from_secs(60))
            .await
            .unwrap(),
        *expected
    );
    assert_eq!(native_state(&source), replay_state_for_test(&replica).await);
}

async fn recovery_driver(seed: u64, coalesced: bool, inclusive: bool, local: bool) {
    for profile in [
        crate::FencedTransitionV2Profile::V2,
        crate::FencedTransitionV2Profile::V2WithLeaseDeferral,
    ] {
        let (mut native, _, live) = changes::tests::fixture_with_profile(profile);
        let template = live.lease().key().clone();
        let clock = Arc::new(ReplayClock(std::sync::Mutex::new(time(2))));
        let fake = replay_prefix(&native, clock.clone()).await;
        let mut journal = native
            .business
            .replication_log(1, 4096, &|| Ok(()))
            .unwrap();
        let mut watch = SessionStore::new(fake.clone())
            .watch(fake.max_replication_sequence().await.unwrap() + 1)
            .await
            .unwrap();
        let mut random = seed;
        let mut second = 2;
        let mut trace = Vec::new();
        let mut slices = 0;
        let mut recoveries = 0;
        for group in 0..24 {
            let choice = draw(&mut random);
            let mut serial = native.clone();
            let mut commands = Vec::new();
            let mut expected = Vec::new();
            let mut old = None;
            let kinds = [
                0,
                1 + choice % 2,
                3,
                (choice >> 8) % 3,
                if choice & 1 == 0 { 3 } else { 2 },
            ];
            for (position, kind) in kinds.into_iter().enumerate() {
                second += 1 + draw(&mut random) % 3;
                let now = time(0).add_seconds(second as i64).unwrap();
                let index = serial.business.applied().unwrap().index + 1;
                let target = key(&template, 60_000 + group * 8 + position as u64);
                let mut entry = if kind == 3 {
                    let era = serial
                        .business
                        .frontiers
                        .async_recovery
                        .as_ref()
                        .map_or(2, |r| r.era + 1);
                    let mut entry = recovery(&serial, index, era);
                    if let EntryPayload::Normal(command) = &mut entry.payload {
                        command.logical_time = now;
                    }
                    entry
                } else if kind == 1 {
                    let floor = serial
                        .business
                        .observe_at(&target, now)
                        .unwrap()
                        .current_fence()
                        .get();
                    let request = key_retention_tests::ephemeral_request(
                        target,
                        60_000 + group * 8 + position as u64,
                        floor,
                        serial
                            .business
                            .history_state()
                            .unwrap()
                            .active_epoch()
                            .unwrap(),
                        now,
                    );
                    changes::tests::command(index, &request, now, false)
                } else {
                    let intent = if kind == 0 {
                        SessionMutationIntent::AcquireLease {
                            key: target,
                            owner: crate::OwnerId::new("seeded-slice-owner").unwrap(),
                            ttl: Duration::from_secs(60),
                        }
                    } else {
                        SessionMutationIntent::AdvanceLogicalTime
                    };
                    key_retention_tests::command_at(index, intent, now)
                };
                if kind != 3 {
                    entry.log_id.leader_id = serial.business.applied().unwrap().leader_id;
                }
                let applied = apply(&mut serial, std::slice::from_ref(&entry));
                assert!(
                    applied.responses.iter().all(|r| r.result.is_ok()),
                    "seed={seed:#x} trace={trace:?}"
                );
                if position == 0 {
                    let Ok(SessionMutationOutcome::Lease(lease)) = &applied.responses[0].result
                    else {
                        panic!("initial acquisition")
                    };
                    old = Some(lease.clone());
                }
                trace.push((group, position, kind, second));
                for row in applied.notifications {
                    expected.push((row, serial.clone(), old.clone().unwrap()));
                }
                commands.push(entry);
            }
            let mut actual = Vec::new();
            if coalesced {
                actual.extend(apply(&mut native, &commands).notifications);
                slices += 1;
            } else {
                for entry in commands {
                    actual.extend(apply(&mut native, &[entry]).notifications);
                }
            }
            assert_eq!(
                actual,
                expected
                    .iter()
                    .map(|(row, _, _)| row.clone())
                    .collect::<Vec<_>>(),
                "seed={seed:#x} profile={profile:?} trace={trace:?}"
            );
            for (row, checkpoint, old) in expected {
                *clock.0.lock().unwrap() = row.timestamp;
                fake.replicate_entry(row.clone())
                    .await
                    .unwrap_or_else(|error| {
                        panic!(
                            "committed replay refused: {error:?}; seed={seed:#x} trace={trace:?}"
                        )
                    });
                assert_eq!(
                    native_state(&checkpoint),
                    replay_state_for_test(&fake).await,
                    "seed={seed:#x} trace={trace:?}"
                );
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(2), watch.next())
                        .await
                        .unwrap()
                        .unwrap()
                        .unwrap(),
                    row
                );
                journal.push(row.clone());
                if matches!(
                    row.replay_policy.recovery,
                    crate::ReplicationRecoveryBoundary::Recover { .. }
                ) {
                    recoveries += 1;
                    if inclusive {
                        let mut resumed = SessionStore::new(fake.clone())
                            .watch(row.sequence)
                            .await
                            .unwrap();
                        assert_eq!(resumed.next().await.unwrap().unwrap(), row);
                    }
                    if local {
                        local_recovery_probe(
                            &checkpoint,
                            &journal,
                            &old,
                            clock.clone(),
                            row.timestamp,
                        )
                        .await;
                    }
                }
            }
            assert_eq!(native_state(&native), replay_state_for_test(&fake).await);
        }
        assert!(recoveries >= 24);
        assert_eq!(slices, if coalesced { 24 } else { 0 });
        eprintln!("recovery_seed={seed:#x} profile={profile:?} slices={slices} recoveries={recoveries} inclusive={inclusive} local={local}");
    }
}

#[tokio::test]
async fn round6_seeded_committed_slices_match_each_native_prefix() {
    for seed in SEEDS {
        recovery_driver(seed, true, false, false).await;
    }
}
#[tokio::test]
async fn round6_seeded_inclusive_recovery_watches_are_contiguous() {
    for seed in SEEDS {
        recovery_driver(seed, false, true, false).await;
    }
}
#[tokio::test]
async fn round6_seeded_local_lease_authority_matches_after_recovery() {
    for seed in SEEDS {
        recovery_driver(seed, false, false, true).await;
    }
}

struct SqlReplayDriver {
    source: SqliteSessionBackend,
    replica: SqliteSessionBackend,
    rebuilt: SqliteSessionBackend,
    source_path: std::path::PathBuf,
    replica_path: std::path::PathBuf,
    rebuilt_path: std::path::PathBuf,
    source_clock: Arc<ReplayClock>,
    replica_clock: Arc<ReplayClock>,
    journal: Vec<crate::ReplicationEntry>,
}
impl SqlReplayDriver {
    async fn publish(&mut self, timestamp: Timestamp, op: crate::ReplicationOp) {
        let sequence = self.journal.len() as u64 + 1;
        let mut entry = context(sequence, crate::ReplicationReplayPolicy::prune_expired());
        entry.timestamp = timestamp;
        entry.op = op;
        *self.replica_clock.0.lock().unwrap() = if sequence == 1 {
            timestamp
        } else {
            timestamp.add_seconds(70).unwrap()
        };
        self.replica
            .replicate_entry(entry.clone())
            .await
            .unwrap_or_else(|error| {
                panic!("paused replica refused committed row {sequence}: {error:?}")
            });
        assert_eq!(
            &sqlite_rows(&self.source_path)[..4],
            &sqlite_rows(&self.replica_path)[..4],
            "source/live divergence at entry {sequence}"
        );
        self.journal.push(entry);
        self.rebuilt
            .rebuild_replication_state(self.journal.clone())
            .await
            .unwrap();
        assert_eq!(
            sqlite_rows(&self.replica_path),
            sqlite_rows(&self.rebuilt_path),
            "live/rebuild divergence at entry {sequence}"
        );
    }
}

#[tokio::test]
async fn round6_seeded_paused_sqlite_replicas_match_committed_time() {
    for seed in SEEDS {
        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("source.sqlite");
        let replica_path = directory.path().join("replica.sqlite");
        let rebuilt_path = directory.path().join("rebuilt.sqlite");
        let source_clock = Arc::new(ReplayClock(std::sync::Mutex::new(time(1))));
        let replica_clock = Arc::new(ReplayClock(std::sync::Mutex::new(time(1))));
        let mut driver = SqlReplayDriver {
            source: SqliteSessionBackend::open(&source_path)
                .unwrap()
                .with_clock(source_clock.clone()),
            replica: SqliteSessionBackend::open(&replica_path)
                .unwrap()
                .with_clock(replica_clock.clone()),
            rebuilt: SqliteSessionBackend::open(&rebuilt_path)
                .unwrap()
                .with_clock(replica_clock.clone()),
            source_path,
            replica_path,
            rebuilt_path,
            source_clock,
            replica_clock,
            journal: Vec::new(),
        };
        let (_, _, template) = changes::tests::fixture();
        let mut random = seed;
        let mut second = 1;
        for step in 0..24 {
            let choice = draw(&mut random);
            second += 1 + choice % 4;
            let now = time(0).add_seconds(second as i64).unwrap();
            *driver.source_clock.0.lock().unwrap() = now;
            let key = key(template.lease().key(), 90_000 + choice % 8);
            // The standalone coordinator explicitly performs its declared cleanup.
            driver.source.get(&key).await.unwrap();
            let ttl = Duration::from_secs(60);
            let guard = driver
                .source
                .acquire(&key, crate::OwnerId::new("seeded-sql-owner").unwrap(), ttl)
                .await
                .unwrap();
            driver
                .publish(
                    now,
                    crate::ReplicationOp::AcquireLease {
                        key: key.clone(),
                        owner: guard.owner().clone(),
                        fence: guard.fence(),
                        credential_id: guard.credential_id(),
                        ttl,
                        expires_at: guard.expires_at(),
                    },
                )
                .await;
            second += 1;
            let now = time(0).add_seconds(second as i64).unwrap();
            *driver.source_clock.0.lock().unwrap() = now;
            driver.source.get(&key).await.unwrap();
            let guard = driver.source.renew(&guard, ttl).await.unwrap();
            driver
                .publish(
                    now,
                    crate::ReplicationOp::RenewLease {
                        key: key.clone(),
                        owner: guard.owner().clone(),
                        fence: guard.fence(),
                        credential_id: guard.credential_id(),
                        ttl,
                        expires_at: guard.expires_at(),
                    },
                )
                .await;
            second += 1;
            let now = time(0).add_seconds(second as i64).unwrap();
            *driver.source_clock.0.lock().unwrap() = now;
            let existing = driver.source.get(&key).await.unwrap();
            let expected_generation = existing.as_ref().map(|row| row.generation);
            let generation = expected_generation.map_or(crate::Generation::new(1), |generation| {
                generation.next().unwrap()
            });
            let record = mixed_record(&guard, generation, 90_000 + step, now);
            let result = driver
                .source
                .compare_and_set(crate::CompareAndSet {
                    key: key.clone(),
                    lease: guard.clone(),
                    expected_generation,
                    new_record: record.clone(),
                })
                .await
                .unwrap();
            assert_eq!(result, crate::CompareAndSetResult::Success);
            driver
                .publish(
                    now,
                    crate::ReplicationOp::CompareAndSet {
                        key: key.clone(),
                        expected_generation,
                        credential_id: guard.credential_id(),
                        guard_expires_at: guard.expires_at(),
                        new_record: record,
                    },
                )
                .await;
            second += 1;
            let now = time(0).add_seconds(second as i64).unwrap();
            *driver.source_clock.0.lock().unwrap() = now;
            driver.source.get(&key).await.unwrap();
            let op = if choice & 1 == 0 {
                driver.source.refresh_ttl(&guard, ttl).await.unwrap();
                crate::ReplicationOp::RefreshTtl {
                    key: key.clone(),
                    owner: guard.owner().clone(),
                    fence: guard.fence(),
                    ttl,
                    expires_at: now.add_seconds(60).unwrap(),
                }
            } else {
                driver.source.release(guard.clone()).await.unwrap();
                crate::ReplicationOp::ReleaseLease {
                    key: key.clone(),
                    owner: guard.owner().clone(),
                    fence: guard.fence(),
                    credential_id: guard.credential_id(),
                }
            };
            driver.publish(now, op).await;
        }
        eprintln!("paused_sql_seed={seed:#x} entries={}", driver.journal.len());
    }
}
