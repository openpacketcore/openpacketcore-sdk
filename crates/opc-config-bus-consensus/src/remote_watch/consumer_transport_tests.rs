// Included inside the existing mutual-TLS fixture module. Only synthetic SDK
// identities and configuration values are used by these storage/transport tests.
mod durable_consumer {
    use super::*;
    use crate::remote_watch::consumer::*;
    use opc_key::{
        KeyError, KeyHandle, KeyId, KeyProvider, KeyPurpose, MemoryKeyProvider, Zeroizing,
    };
    use opc_persist::{
        ConsumerCheckpointBinding, ConsumerCheckpointOptions, ConsumerCheckpointStore,
        RetainedConfigDurability,
    };
    use std::path::{Path, PathBuf};

    fn checkpoint_options(
        path: &Path,
        tls: &TestTls,
        binding: ConfigConsensusIdentity,
    ) -> ConsumerCheckpointOptions {
        ConsumerCheckpointOptions::new(
            path,
            ConsumerCheckpointBinding::new(
                binding,
                TEST_SCHEMA_DIGEST,
                tls.client_spiffe_id.clone(),
                TenantId::from_static("test"),
                [0x71; 32],
            )
            .unwrap(),
            RetainedConfigDurability::Ephemeral,
            1024 * 1024,
            16 * 1024 * 1024,
            Duration::from_secs(5),
        )
        .unwrap()
    }

    fn checkpoint_keys() -> Arc<MemoryKeyProvider> {
        let keys = Arc::new(MemoryKeyProvider::new());
        keys.insert_active_key(
            KeyId::new("consumer-test-key").unwrap(),
            KeyPurpose::ConfigConsumerCheckpoint,
            TenantId::from_static("test"),
            Zeroizing::new([0x72; 32]),
        )
        .unwrap();
        keys
    }

    struct KeyGate {
        keys: Arc<MemoryKeyProvider>,
        available: std::sync::atomic::AtomicBool,
    }

    impl KeyGate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                keys: checkpoint_keys(),
                available: std::sync::atomic::AtomicBool::new(true),
            })
        }
        fn check(&self) -> Result<(), KeyError> {
            if self.available.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(KeyError::Unavailable)
            }
        }
    }

    #[async_trait]
    impl KeyProvider for KeyGate {
        async fn get_active_key(
            &self,
            purpose: KeyPurpose,
            tenant: &TenantId,
        ) -> Result<KeyHandle, KeyError> {
            self.check()?;
            self.keys.get_active_key(purpose, tenant).await
        }
        async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
            self.check()?;
            self.keys.get_key_by_id(key_id).await
        }
        async fn rotate_key(
            &self,
            purpose: KeyPurpose,
            tenant: &TenantId,
        ) -> Result<KeyId, KeyError> {
            self.check()?;
            self.keys.rotate_key(purpose, tenant).await
        }
    }

    struct Runtime {
        actual: Option<(TxId, ConfigVersion, String)>,
        applies: usize,
        reads: usize,
        outcome: ConfigApplyOutcome,
        park: bool,
        crash_path: Option<PathBuf>,
        cut_keys: Option<Arc<KeyGate>>,
        read_outcome: Option<ConfigRuntimeReadbackOutcome>,
        entered: Arc<Notify>,
    }

    impl Default for Runtime {
        fn default() -> Self {
            Self {
                actual: None,
                applies: 0,
                reads: 0,
                outcome: ConfigApplyOutcome::Applied,
                park: false,
                crash_path: None,
                cut_keys: None,
                read_outcome: None,
                entered: Arc::new(Notify::new()),
            }
        }
    }

    fn matches(
        actual: &Option<(TxId, ConfigVersion, String)>,
        revision: &ConsumerRevision<TestConfig>,
    ) -> bool {
        actual.as_ref().is_some_and(|(tx, version, value)| {
            *tx == revision.transaction()
                && *version == revision.version()
                && *value == revision.config().value
        })
    }

    #[async_trait]
    impl ConfigConsumerApplyPort<TestConfig> for Runtime {
        async fn apply(
            &mut self,
            intent: &ConfigApplyIntent<TestConfig>,
            _: tokio::time::Instant,
        ) -> ConfigApplyOutcome {
            self.applies += 1;
            if self.outcome == ConfigApplyOutcome::Rejected {
                return self.outcome;
            }
            let target = intent.target();
            self.actual = Some((
                target.transaction(),
                target.version(),
                target.config().value.clone(),
            ));
            self.entered.notify_one();
            if let Some(keys) = &self.cut_keys {
                keys.available.store(false, Ordering::SeqCst);
            }
            if let Some(path) = &self.crash_path {
                std::fs::write(path, serde_json::to_vec(&self.actual).unwrap()).unwrap();
                std::fs::File::open(path).unwrap().sync_all().unwrap();
                std::process::exit(91);
            }
            if self.park {
                std::future::pending::<()>().await;
            }
            self.outcome
        }
        async fn read_back(
            &mut self,
            expected: &ConfigRuntimeReadback<TestConfig>,
            _: tokio::time::Instant,
        ) -> ConfigRuntimeReadbackOutcome {
            self.reads += 1;
            if let Some(outcome) = self.read_outcome {
                return outcome;
            }
            if self.actual.is_none() {
                return ConfigRuntimeReadbackOutcome::Absent;
            }
            if let Some(pending) = expected.pending() {
                if matches(&self.actual, pending.target()) {
                    return ConfigRuntimeReadbackOutcome::MatchesTarget;
                }
                if pending.previous().is_some_and(|p| matches(&self.actual, p)) {
                    return ConfigRuntimeReadbackOutcome::MatchesPrevious;
                }
            } else if expected
                .last_known_applied()
                .is_some_and(|p| matches(&self.actual, p))
            {
                return ConfigRuntimeReadbackOutcome::MatchesTarget;
            }
            ConfigRuntimeReadbackOutcome::Conflict
        }
    }

    #[tokio::test]
    async fn consumer_restart_preserves_floor_and_does_not_infer_application() {
        let tls = TestTls::new(71);
        let binding = scope(71);
        let dir = tempfile::tempdir().unwrap();
        let options = checkpoint_options(&dir.path().join("checkpoint.sqlite"), &tls, binding);
        let keys = checkpoint_keys();
        let (bus, _, txs) = seeded_shadow(&["synthetic-v1", "synthetic-v2"]).await;
        let (server, address) = start_server(bus, &tls, binding).await;
        let store = ConsumerCheckpointStore::provision(options.clone(), keys.clone())
            .await
            .unwrap();
        let mut consumer =
            DurableConfigConsumer::new(tls.remote(binding, address), store, Duration::from_secs(3))
                .await
                .unwrap();
        let mut runtime = Runtime::default();
        assert_eq!(
            consumer.status().phase,
            ConfigConsumerPhase::ReadbackRequired
        );
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        assert_eq!(
            consumer.replace_snapshot().await.unwrap(),
            ConfigAcceptanceOutcome::Accepted
        );
        assert_eq!(consumer.status().phase, ConfigConsumerPhase::Observed);
        assert_eq!(runtime.applies, 0);
        consumer.shutdown().await.unwrap();
        server.shutdown().await;

        let (lagging, _, _) = seeded_shadow(&["synthetic-v1"]).await;
        let (server, address) = start_server(lagging, &tls, binding).await;
        let reopened = ConsumerCheckpointStore::reopen(options.clone(), keys.clone())
            .await
            .unwrap();
        let mut consumer = DurableConfigConsumer::new(
            tls.remote(binding, address),
            reopened,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert!(!consumer.status().remote_revalidated);
        assert_eq!(
            consumer.replace_snapshot().await.unwrap_err(),
            ConfigConsumerError::Remote(ConfigWatchError::HistoryCursorAhead)
        );
        assert_eq!(runtime.applies, 0);
        consumer.shutdown().await.unwrap();
        server.shutdown().await;

        // Restore exact original transactions, rather than generating a new
        // revision or pretending a snapshot conveys authoring metadata.
        let store = Arc::new(MockManagedDatastore::new());
        store.seed(record(1, txs[0], None, "synthetic-v1")).await;
        store
            .seed(record(2, txs[1], Some(txs[0]), "synthetic-v2"))
            .await;
        let bus = ConfigBus::restore_shadow(AppliedStore {
            inner: store,
            compacted: false,
            probe: None,
        })
        .await
        .unwrap();
        let (server, address) = start_server(Arc::new(bus), &tls, binding).await;
        let reopened = ConsumerCheckpointStore::reopen(options, keys)
            .await
            .unwrap();
        let mut consumer = DurableConfigConsumer::new(
            tls.remote(binding, address),
            reopened,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        assert_eq!(
            consumer.replace_snapshot().await.unwrap(),
            ConfigAcceptanceOutcome::AlreadyAccepted
        );
        assert_eq!(
            consumer.apply_observed(&mut runtime).await.unwrap(),
            ConfigConsumerApplyResult::Applied
        );
        assert_eq!(
            runtime.actual,
            Some((txs[1], ConfigVersion::new(2), "synthetic-v2".into()))
        );
        consumer.shutdown().await.unwrap();
        server.shutdown().await;
    }

    #[tokio::test]
    async fn applied_checkpoint_on_restart_requires_actual_runtime_readback() {
        let tls = TestTls::new(72);
        let binding = scope(72);
        let dir = tempfile::tempdir().unwrap();
        let options = checkpoint_options(&dir.path().join("checkpoint.sqlite"), &tls, binding);
        let keys = checkpoint_keys();
        let (bus, _, _) = seeded_shadow(&["synthetic-applied"]).await;
        let (server, address) = start_server(bus, &tls, binding).await;
        let store = ConsumerCheckpointStore::provision(options.clone(), keys.clone())
            .await
            .unwrap();
        let mut consumer =
            DurableConfigConsumer::new(tls.remote(binding, address), store, Duration::from_secs(3))
                .await
                .unwrap();
        let mut runtime = Runtime::default();
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        consumer.replace_snapshot().await.unwrap();
        consumer.apply_observed(&mut runtime).await.unwrap();
        assert_eq!(consumer.status().phase, ConfigConsumerPhase::Applied);
        consumer.shutdown().await.unwrap();
        let store = ConsumerCheckpointStore::reopen(options, keys)
            .await
            .unwrap();
        let mut consumer =
            DurableConfigConsumer::new(tls.remote(binding, address), store, Duration::from_secs(3))
                .await
                .unwrap();
        assert_eq!(
            consumer.status().phase,
            ConfigConsumerPhase::ReadbackRequired
        );
        assert_eq!(
            consumer.apply_observed(&mut runtime).await.unwrap_err(),
            ConfigConsumerError::ReadbackRequired
        );
        assert_eq!(runtime.applies, 1);
        runtime.actual = None;
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        assert_eq!(consumer.status().phase, ConfigConsumerPhase::Observed);
        consumer.replace_snapshot().await.unwrap();
        consumer.apply_observed(&mut runtime).await.unwrap();
        assert_eq!(runtime.applies, 2);
        consumer.shutdown().await.unwrap();
        server.shutdown().await;
    }

    #[tokio::test]
    async fn cancelled_and_indeterminate_apply_are_reconciled_without_replay() {
        for parked in [false, true] {
            let tls = TestTls::new(73);
            let binding = scope(73);
            let dir = tempfile::tempdir().unwrap();
            let options = checkpoint_options(&dir.path().join("checkpoint.sqlite"), &tls, binding);
            let keys = checkpoint_keys();
            let (bus, _, _) = seeded_shadow(&["synthetic-pending"]).await;
            let (server, address) = start_server(bus, &tls, binding).await;
            let store = ConsumerCheckpointStore::provision(options.clone(), keys.clone())
                .await
                .unwrap();
            let mut consumer = DurableConfigConsumer::new(
                tls.remote(binding, address),
                store,
                Duration::from_secs(3),
            )
            .await
            .unwrap();
            let mut runtime = Runtime {
                park: parked,
                outcome: ConfigApplyOutcome::Indeterminate,
                ..Runtime::default()
            };
            consumer.reconcile_runtime(&mut runtime).await.unwrap();
            consumer.replace_snapshot().await.unwrap();
            if parked {
                let entered = Arc::clone(&runtime.entered);
                tokio::select! { biased; result = consumer.apply_observed(&mut runtime) => panic!("parked apply completed: {result:?}"), _ = entered.notified() => {} }
            } else {
                assert_eq!(
                    consumer.apply_observed(&mut runtime).await.unwrap(),
                    ConfigConsumerApplyResult::Indeterminate
                );
            }
            assert_eq!(consumer.status().phase, ConfigConsumerPhase::ApplyPending);
            assert_eq!(
                consumer.apply_observed(&mut runtime).await.unwrap_err(),
                ConfigConsumerError::ReadbackRequired
            );
            consumer.shutdown().await.unwrap();
            let store = ConsumerCheckpointStore::reopen(options, keys)
                .await
                .unwrap();
            let mut consumer = DurableConfigConsumer::new(
                tls.remote(binding, address),
                store,
                Duration::from_secs(3),
            )
            .await
            .unwrap();
            assert_eq!(consumer.status().phase, ConfigConsumerPhase::ApplyPending);
            consumer.reconcile_runtime(&mut runtime).await.unwrap();
            assert_eq!(consumer.status().phase, ConfigConsumerPhase::Applied);
            assert_eq!(runtime.applies, 1);
            consumer.replace_snapshot().await.unwrap();
            assert_eq!(
                consumer.apply_observed(&mut runtime).await.unwrap(),
                ConfigConsumerApplyResult::AlreadyApplied
            );
            consumer.shutdown().await.unwrap();
            server.shutdown().await;
        }
    }

    #[tokio::test]
    async fn process_crash_during_apply_child() {
        let Some(directory) = std::env::var_os("OPC_CONSUMER_CHECKPOINT_CRASH_TEST") else {
            return;
        };
        let directory = PathBuf::from(directory);
        let tls = TestTls::new(74);
        let binding = scope(74);
        let options = checkpoint_options(&directory.join("checkpoint.sqlite"), &tls, binding);
        let (bus, _, _) = seeded_shadow(&["synthetic-crash-target"]).await;
        let (_server, address) = start_server(bus, &tls, binding).await;
        let store = ConsumerCheckpointStore::provision(options, checkpoint_keys())
            .await
            .unwrap();
        let mut consumer =
            DurableConfigConsumer::new(tls.remote(binding, address), store, Duration::from_secs(3))
                .await
                .unwrap();
        let mut runtime = Runtime {
            crash_path: Some(directory.join("runtime.json")),
            ..Runtime::default()
        };
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        consumer.replace_snapshot().await.unwrap();
        consumer.apply_observed(&mut runtime).await.unwrap();
        panic!("crash boundary was not reached");
    }

    #[tokio::test]
    async fn process_loss_proves_checkpoint_precedes_product_apply() {
        let directory = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "remote_watch::tests::durable_consumer::process_crash_during_apply_child",
                "--nocapture",
            ])
            .env("OPC_CONSUMER_CHECKPOINT_CRASH_TEST", directory.path())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(91),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let tls = TestTls::new(74);
        let binding = scope(74);
        let options =
            checkpoint_options(&directory.path().join("checkpoint.sqlite"), &tls, binding);
        let store = ConsumerCheckpointStore::reopen(options, checkpoint_keys())
            .await
            .unwrap();
        let mut consumer = DurableConfigConsumer::new(
            tls.remote(binding, "127.0.0.1:9".parse().unwrap()),
            store,
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        assert_eq!(
            consumer.status().phase,
            ConfigConsumerPhase::ApplyPending,
            "product effects started before durable apply intent"
        );
        let mut runtime = Runtime {
            actual: serde_json::from_slice(
                &std::fs::read(directory.path().join("runtime.json")).unwrap(),
            )
            .unwrap(),
            ..Runtime::default()
        };
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        assert_eq!(consumer.status().phase, ConfigConsumerPhase::Applied);
        assert_eq!(runtime.applies, 0);
        assert!(!consumer.status().remote_revalidated);
        consumer.shutdown().await.unwrap();
    }
    async fn original_shadow(
        entries: &[(u64, TxId, &str)],
        compacted: bool,
    ) -> (
        Arc<ConfigBus<TestConfig>>,
        Arc<MockManagedDatastore<TestConfig>>,
    ) {
        let store = Arc::new(MockManagedDatastore::new());
        let mut parent = None;
        for (version, tx, value) in entries {
            store.seed(record(*version, *tx, parent, value)).await;
            parent = Some(*tx);
        }
        let bus = ConfigBus::restore_shadow(AppliedStore {
            inner: Arc::clone(&store),
            compacted,
            probe: None,
        })
        .await
        .unwrap();
        (Arc::new(bus), store)
    }

    #[tokio::test]
    async fn conflicting_same_version_transaction_or_payload_cannot_replace_checkpoint() {
        for conflicting_payload in [false, true] {
            let tls = TestTls::new(75);
            let binding = scope(75);
            let tx = TxId::new();
            let dir = tempfile::tempdir().unwrap();
            let options = checkpoint_options(&dir.path().join("checkpoint.sqlite"), &tls, binding);
            let keys = checkpoint_keys();
            let (bus, _) = original_shadow(&[(1, tx, "synthetic-original")], false).await;
            let (server, address) = start_server(bus, &tls, binding).await;
            let store = ConsumerCheckpointStore::provision(options.clone(), keys.clone())
                .await
                .unwrap();
            let mut consumer = DurableConfigConsumer::new(
                tls.remote(binding, address),
                store,
                Duration::from_secs(3),
            )
            .await
            .unwrap();
            let mut runtime = Runtime::default();
            consumer.reconcile_runtime(&mut runtime).await.unwrap();
            consumer.replace_snapshot().await.unwrap();
            consumer.shutdown().await.unwrap();
            server.shutdown().await;
            let (changed_tx, value) = if conflicting_payload {
                (tx, "synthetic-conflict")
            } else {
                (TxId::new(), "synthetic-original")
            };
            let (bus, _) = original_shadow(&[(1, changed_tx, value)], false).await;
            let (server, address) = start_server(bus, &tls, binding).await;
            let store = ConsumerCheckpointStore::reopen(options.clone(), keys.clone())
                .await
                .unwrap();
            let mut consumer = DurableConfigConsumer::new(
                tls.remote(binding, address),
                store,
                Duration::from_secs(3),
            )
            .await
            .unwrap();
            consumer.reconcile_runtime(&mut runtime).await.unwrap();
            assert_eq!(
                consumer.replace_snapshot().await.unwrap_err(),
                ConfigConsumerError::RevisionConflict
            );
            assert!(!consumer.status().remote_revalidated);
            assert_eq!(runtime.applies, 0);
            consumer.shutdown().await.unwrap();
            server.shutdown().await;
            let (bus, _) = original_shadow(&[(1, tx, "synthetic-original")], false).await;
            let (server, address) = start_server(bus, &tls, binding).await;
            let store = ConsumerCheckpointStore::reopen(options, keys)
                .await
                .unwrap();
            let mut consumer = DurableConfigConsumer::new(
                tls.remote(binding, address),
                store,
                Duration::from_secs(3),
            )
            .await
            .unwrap();
            consumer.reconcile_runtime(&mut runtime).await.unwrap();
            assert_eq!(
                consumer.replace_snapshot().await.unwrap(),
                ConfigAcceptanceOutcome::AlreadyAccepted
            );
            consumer.apply_observed(&mut runtime).await.unwrap();
            assert_eq!(runtime.actual.unwrap().0, tx);
            consumer.shutdown().await.unwrap();
            server.shutdown().await;
        }
    }

    #[tokio::test]
    async fn compacted_replacement_keeps_applied_fact_then_resumes_an_exact_tail() {
        let tls = TestTls::new(76);
        let binding = scope(76);
        let first = TxId::new();
        let fourth = TxId::new();
        let fifth = TxId::new();
        let dir = tempfile::tempdir().unwrap();
        let options = checkpoint_options(&dir.path().join("checkpoint.sqlite"), &tls, binding);
        let keys = checkpoint_keys();
        let history = Arc::new(MockManagedDatastore::new());
        history.seed(record(1, first, None, "synthetic-v1")).await;
        let probe = Arc::new(AppliedStoreProbe::default());
        let bus = Arc::new(
            ConfigBus::restore_shadow(AppliedStore {
                inner: history.clone(),
                compacted: false,
                probe: Some(probe.clone()),
            })
            .await
            .unwrap(),
        );
        let (server, address) = start_server(bus, &tls, binding).await;
        let store = ConsumerCheckpointStore::provision(options.clone(), keys.clone())
            .await
            .unwrap();
        let mut consumer =
            DurableConfigConsumer::new(tls.remote(binding, address), store, Duration::from_secs(3))
                .await
                .unwrap();
        let mut runtime = Runtime::default();
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        consumer.replace_snapshot().await.unwrap();
        consumer.apply_observed(&mut runtime).await.unwrap();
        history
            .seed(record(4, fourth, Some(first), "synthetic-v4"))
            .await;
        probe.compacted_before.store(4, Ordering::SeqCst);
        assert_eq!(
            consumer.accept_next().await.unwrap_err(),
            ConfigConsumerError::Remote(ConfigWatchError::HistoryCompacted)
        );
        consumer.replace_snapshot().await.unwrap();
        assert_eq!(consumer.status().phase, ConfigConsumerPhase::Observed);
        assert_eq!(runtime.actual.as_ref().unwrap().1, ConfigVersion::new(1));
        assert_eq!(runtime.applies, 1);
        consumer.shutdown().await.unwrap();
        let store = ConsumerCheckpointStore::reopen(options, keys)
            .await
            .unwrap();
        let mut consumer =
            DurableConfigConsumer::new(tls.remote(binding, address), store, Duration::from_secs(3))
                .await
                .unwrap();
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        assert_eq!(
            consumer.replace_snapshot().await.unwrap(),
            ConfigAcceptanceOutcome::AlreadyAccepted
        );
        consumer.apply_observed(&mut runtime).await.unwrap();
        assert_eq!(runtime.applies, 2);
        history
            .seed(record(5, fifth, Some(fourth), "synthetic-v5"))
            .await;
        assert_eq!(
            consumer.accept_next().await.unwrap(),
            ConfigAcceptanceOutcome::Accepted
        );
        assert_eq!(runtime.applies, 2);
        assert_eq!(consumer.status().phase, ConfigConsumerPhase::Observed);
        consumer.apply_observed(&mut runtime).await.unwrap();
        assert_eq!(runtime.actual.unwrap().0, fifth);
        assert_eq!(runtime.applies, 3);
        consumer.shutdown().await.unwrap();
        server.shutdown().await;
    }

    #[tokio::test]
    async fn gap_or_wrong_authenticated_scope_never_changes_accepted_floor() {
        let tls = TestTls::new(77);
        let binding = scope(77);
        let first = TxId::new();
        let dir = tempfile::tempdir().unwrap();
        let options = checkpoint_options(&dir.path().join("checkpoint.sqlite"), &tls, binding);
        let keys = checkpoint_keys();
        let (bus, history) = original_shadow(&[(1, first, "synthetic-v1")], false).await;
        let (server, address) = start_server(bus, &tls, binding).await;
        let store = ConsumerCheckpointStore::provision(options.clone(), keys.clone())
            .await
            .unwrap();
        let mut consumer =
            DurableConfigConsumer::new(tls.remote(binding, address), store, Duration::from_secs(3))
                .await
                .unwrap();
        let mut runtime = Runtime::default();
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        consumer.replace_snapshot().await.unwrap();
        history
            .seed(record(3, TxId::new(), Some(first), "synthetic-v3"))
            .await;
        assert_eq!(
            consumer.accept_next().await.unwrap_err(),
            ConfigConsumerError::Remote(ConfigWatchError::InvalidHistorySequence)
        );
        assert_eq!(runtime.applies, 0);
        consumer.shutdown().await.unwrap();
        server.shutdown().await;
        let (bus, _) = original_shadow(&[(1, first, "synthetic-v1")], false).await;
        let (server, address) = start_server(bus, &tls, scope(78)).await;
        let store = ConsumerCheckpointStore::reopen(options.clone(), keys.clone())
            .await
            .unwrap();
        let mut consumer =
            DurableConfigConsumer::new(tls.remote(binding, address), store, Duration::from_secs(3))
                .await
                .unwrap();
        assert_eq!(
            consumer.replace_snapshot().await.unwrap_err(),
            ConfigConsumerError::Remote(ConfigWatchError::ScopeMismatch)
        );
        consumer.shutdown().await.unwrap();
        server.shutdown().await;
        let store = ConsumerCheckpointStore::reopen(options, keys)
            .await
            .unwrap();
        assert_eq!(
            DurableConfigConsumer::new(
                tls.remote(scope(79), address),
                store,
                Duration::from_secs(3)
            )
            .await
            .unwrap_err(),
            ConfigConsumerError::ScopeMismatch
        );
    }

    #[tokio::test]
    async fn unauthenticated_server_cannot_start_apply() {
        let tls = TestTls::new(79);
        let binding = scope(79);
        let dir = tempfile::tempdir().unwrap();
        let options = checkpoint_options(&dir.path().join("checkpoint.sqlite"), &tls, binding);
        let keys = checkpoint_keys();
        let (bus, _, _) = seeded_shadow(&["synthetic-v1"]).await;
        let foreign = TestTls::new(80);
        let (server, address) = start_server(bus, &foreign, binding).await;
        let store = ConsumerCheckpointStore::provision(options, keys)
            .await
            .unwrap();
        let mut consumer =
            DurableConfigConsumer::new(tls.remote(binding, address), store, Duration::from_secs(3))
                .await
                .unwrap();
        assert!(matches!(
            consumer.replace_snapshot().await,
            Err(ConfigConsumerError::Remote(
                ConfigWatchError::Authentication
            ))
        ));
        let mut runtime = Runtime::default();
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        assert_eq!(consumer.status().phase, ConfigConsumerPhase::Unobserved);
        assert_eq!(runtime.applies, 0);
        consumer.shutdown().await.unwrap();
        server.shutdown().await;
    }

    #[tokio::test]
    async fn checkpoint_key_outage_before_and_after_apply_never_authorizes_replay() {
        let tls = TestTls::new(81);
        let binding = scope(81);
        let dir = tempfile::tempdir().unwrap();
        let options = checkpoint_options(&dir.path().join("checkpoint.sqlite"), &tls, binding);
        let keys = KeyGate::new();
        let (bus, _, _) = seeded_shadow(&["synthetic-key-outage"]).await;
        let (server, address) = start_server(bus, &tls, binding).await;
        let store = ConsumerCheckpointStore::provision(options.clone(), keys.clone())
            .await
            .unwrap();
        let mut consumer =
            DurableConfigConsumer::new(tls.remote(binding, address), store, Duration::from_secs(3))
                .await
                .unwrap();
        let mut runtime = Runtime::default();
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        keys.available.store(false, Ordering::SeqCst);
        assert!(matches!(
            consumer.replace_snapshot().await,
            Err(ConfigConsumerError::Checkpoint(_))
        ));
        assert_eq!(
            consumer.status().phase,
            ConfigConsumerPhase::ReadbackRequired
        );
        assert_eq!(
            consumer.apply_observed(&mut runtime).await.unwrap_err(),
            ConfigConsumerError::ReadbackRequired
        );
        assert_eq!(runtime.applies, 0);
        keys.available.store(true, Ordering::SeqCst);
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        assert_eq!(consumer.status().phase, ConfigConsumerPhase::Unobserved);
        consumer.replace_snapshot().await.unwrap();
        keys.available.store(false, Ordering::SeqCst);
        assert!(matches!(
            consumer.apply_observed(&mut runtime).await,
            Err(ConfigConsumerError::Checkpoint(_))
        ));
        assert_eq!(runtime.applies, 0);
        keys.available.store(true, Ordering::SeqCst);
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        consumer.replace_snapshot().await.unwrap();
        runtime.cut_keys = Some(keys.clone());
        assert!(matches!(
            consumer.apply_observed(&mut runtime).await,
            Err(ConfigConsumerError::Checkpoint(_))
        ));
        assert_eq!(runtime.applies, 1);
        assert_eq!(
            consumer.status().phase,
            ConfigConsumerPhase::ReadbackRequired
        );
        assert_eq!(
            consumer.apply_observed(&mut runtime).await.unwrap_err(),
            ConfigConsumerError::ReadbackRequired
        );
        consumer.shutdown().await.unwrap();
        assert!(
            ConsumerCheckpointStore::reopen(options.clone(), keys.clone())
                .await
                .is_err()
        );
        keys.available.store(true, Ordering::SeqCst);
        let store = ConsumerCheckpointStore::reopen(options, keys)
            .await
            .unwrap();
        let mut consumer =
            DurableConfigConsumer::new(tls.remote(binding, address), store, Duration::from_secs(3))
                .await
                .unwrap();
        assert_eq!(consumer.status().phase, ConfigConsumerPhase::ApplyPending);
        runtime.cut_keys = None;
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        assert_eq!(runtime.applies, 1);
        consumer.replace_snapshot().await.unwrap();
        assert_eq!(
            consumer.apply_observed(&mut runtime).await.unwrap(),
            ConfigConsumerApplyResult::AlreadyApplied
        );
        assert_eq!(runtime.applies, 1);
        consumer.shutdown().await.unwrap();
        server.shutdown().await;
    }

    #[tokio::test]
    async fn rejection_and_conflicting_readback_preserve_the_previous_complete_projection() {
        let tls = TestTls::new(82);
        let binding = scope(82);
        let dir = tempfile::tempdir().unwrap();
        let options = checkpoint_options(&dir.path().join("checkpoint.sqlite"), &tls, binding);
        let (bus, history, txs) = seeded_shadow(&["synthetic-v1"]).await;
        let (server, address) = start_server(bus, &tls, binding).await;
        let store = ConsumerCheckpointStore::provision(options, checkpoint_keys())
            .await
            .unwrap();
        let mut consumer =
            DurableConfigConsumer::new(tls.remote(binding, address), store, Duration::from_secs(3))
                .await
                .unwrap();
        let mut runtime = Runtime::default();
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        consumer.replace_snapshot().await.unwrap();
        consumer.apply_observed(&mut runtime).await.unwrap();
        let previous = runtime.actual.clone();
        let second = TxId::new();
        history
            .seed(record(2, second, Some(txs[0]), "synthetic-v2"))
            .await;
        consumer.accept_next().await.unwrap();
        runtime.outcome = ConfigApplyOutcome::Rejected;
        assert_eq!(
            consumer.apply_observed(&mut runtime).await.unwrap(),
            ConfigConsumerApplyResult::Rejected
        );
        assert_eq!(runtime.actual, previous);
        assert_eq!(consumer.status().phase, ConfigConsumerPhase::Observed);
        runtime.outcome = ConfigApplyOutcome::Indeterminate;
        assert_eq!(
            consumer.apply_observed(&mut runtime).await.unwrap(),
            ConfigConsumerApplyResult::Indeterminate
        );
        let applies = runtime.applies;
        for unresolved in [
            ConfigRuntimeReadbackOutcome::Conflict,
            ConfigRuntimeReadbackOutcome::Indeterminate,
        ] {
            runtime.read_outcome = Some(unresolved);
            assert_eq!(
                consumer.reconcile_runtime(&mut runtime).await.unwrap_err(),
                ConfigConsumerError::RuntimeUnresolved
            );
            assert_eq!(consumer.status().phase, ConfigConsumerPhase::ApplyPending);
            assert_eq!(
                consumer.apply_observed(&mut runtime).await.unwrap_err(),
                ConfigConsumerError::ReadbackRequired
            );
            assert_eq!(runtime.applies, applies);
        }
        runtime.read_outcome = None;
        runtime.actual = previous;
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        assert_eq!(consumer.status().phase, ConfigConsumerPhase::Observed);
        assert_eq!(runtime.applies, applies);
        consumer.replace_snapshot().await.unwrap();
        runtime.outcome = ConfigApplyOutcome::Applied;
        consumer.apply_observed(&mut runtime).await.unwrap();
        assert_eq!(runtime.actual.unwrap().0, second);
        consumer.shutdown().await.unwrap();
        server.shutdown().await;
    }

    #[tokio::test]
    async fn complete_apply_intent_must_fit_the_aggregate_checkpoint_budget() {
        let tls = TestTls::new(83);
        let binding = scope(83);
        let dir = tempfile::tempdir().unwrap();
        let options = ConsumerCheckpointOptions::new(
            dir.path().join("checkpoint.sqlite"),
            ConsumerCheckpointBinding::new(
                binding,
                TEST_SCHEMA_DIGEST,
                tls.client_spiffe_id.clone(),
                TenantId::from_static("test"),
                [0x71; 32],
            )
            .unwrap(),
            RetainedConfigDurability::Ephemeral,
            4096,
            1024 * 1024,
            Duration::from_secs(5),
        )
        .unwrap();
        let value = "x".repeat(2300);
        let (bus, _, _) = seeded_shadow(&[&value]).await;
        let (server, address) = start_server(bus, &tls, binding).await;
        let store = ConsumerCheckpointStore::provision(options, checkpoint_keys())
            .await
            .unwrap();
        let mut consumer =
            DurableConfigConsumer::new(tls.remote(binding, address), store, Duration::from_secs(3))
                .await
                .unwrap();
        let mut runtime = Runtime::default();
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        consumer.replace_snapshot().await.unwrap();
        assert_eq!(
            consumer.apply_observed(&mut runtime).await.unwrap_err(),
            ConfigConsumerError::Limit
        );
        assert_eq!(runtime.applies, 0);
        assert_eq!(consumer.status().phase, ConfigConsumerPhase::Observed);
        consumer.shutdown().await.unwrap();
        server.shutdown().await;
    }
}
