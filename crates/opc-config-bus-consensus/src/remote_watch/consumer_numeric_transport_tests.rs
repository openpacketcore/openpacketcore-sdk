mod numeric {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct NumericConfig {
        unsigned: Vec<u128>,
        signed: Vec<i128>,
    }

    impl OpcConfig for NumericConfig {
        type Delta = Self;

        fn schema_digest(&self) -> SchemaDigest {
            TEST_SCHEMA_DIGEST
        }

        fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
            Ok(if self == previous {
                Vec::new()
            } else {
                vec![self.clone()]
            })
        }

        fn changed_paths(
            &self,
            _: &Self,
            deltas: &[Self::Delta],
        ) -> Result<Vec<YangPath>, ConfigError> {
            Ok(if deltas.is_empty() {
                Vec::new()
            } else {
                vec![YangPath::new("/system/integers").unwrap()]
            })
        }

        fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
            *self = delta;
            Ok(())
        }

        fn validate_syntax(&self) -> Result<(), ValidationError> {
            Ok(())
        }

        fn validate_semantics(&self, _: &ValidationContext<Self>) -> Result<(), ValidationError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct NumericRuntime {
        actual: Option<(TxId, ConfigVersion, NumericConfig)>,
        applies: usize,
    }

    #[async_trait]
    impl ConfigConsumerApplyPort<NumericConfig> for NumericRuntime {
        async fn apply(
            &mut self,
            intent: &ConfigApplyIntent<NumericConfig>,
            _: tokio::time::Instant,
        ) -> ConfigApplyOutcome {
            self.applies += 1;
            let target = intent.target();
            self.actual = Some((
                target.transaction(),
                target.version(),
                target.config().clone(),
            ));
            ConfigApplyOutcome::Applied
        }

        async fn read_back(
            &mut self,
            expected: &ConfigRuntimeReadback<NumericConfig>,
            _: tokio::time::Instant,
        ) -> ConfigRuntimeReadbackOutcome {
            let Some(actual) = &self.actual else {
                return ConfigRuntimeReadbackOutcome::Absent;
            };
            let target = expected
                .pending()
                .map(ConfigApplyIntent::target)
                .or_else(|| expected.last_known_applied());
            if target.is_some_and(|target| {
                actual.0 == target.transaction()
                    && actual.1 == target.version()
                    && actual.2 == *target.config()
            }) {
                ConfigRuntimeReadbackOutcome::MatchesTarget
            } else {
                ConfigRuntimeReadbackOutcome::Conflict
            }
        }
    }

    #[tokio::test]
    async fn consumer_preserves_integer_boundaries_through_transport_checkpoint_and_restart() {
        let config = NumericConfig {
            unsigned: vec![
                0,
                u64::MAX as u128,
                u64::MAX as u128 + 1,
                u128::MAX - 1,
                u128::MAX,
            ],
            signed: vec![
                i128::MIN,
                i64::MIN as i128 - 1,
                i64::MIN as i128,
                0,
                i128::MAX,
            ],
        };
        let tls = TestTls::new(90);
        let binding = scope(90);
        let tx = TxId::new();
        let store = Arc::new(MockManagedDatastore::new());
        store
            .seed(StoredConfig {
                tx_id: tx,
                parent_tx_id: None,
                version: ConfigVersion::new(1),
                committed_at: Timestamp::from_str("2026-07-16T00:00:00Z").unwrap(),
                principal: principal(),
                source: RequestSource::Internal,
                schema_digest: TEST_SCHEMA_DIGEST,
                plaintext_digest: None,
                config: config.clone(),
                encrypted_blob: Vec::new(),
                idempotency_key: None,
                apply_plan: None,
                request_fingerprint: None,
                request_id: None,
                recovery_required: false,
                confirmed_deadline: None,
                rollback_label: None,
            })
            .await;
        let bus = ConfigBus::restore_shadow(AppliedStore {
            inner: store,
            compacted: false,
            probe: None,
        })
        .await
        .unwrap();
        let (server, address) = start_server(Arc::new(bus), &tls, binding).await;
        let remote = || {
            RemoteConfigWatch::<NumericConfig>::new(
                ConfigWatchClientBinding::new(
                    binding,
                    tls.client_spiffe_id.clone(),
                    tls.server_spiffe_id.clone(),
                    TEST_SCHEMA_DIGEST,
                ),
                fixed_config_watch_endpoint(address),
                tls.client_config.clone(),
            )
        };
        // Establish that the actual authenticated typed wire path carries every
        // integer exactly before exercising consumer canonicalization/storage.
        let (snapshot, tail) = remote().recover_from(None).await.unwrap().into_parts();
        assert_eq!(snapshot.tx_id, Some(tx));
        assert_eq!(*snapshot.config, config);
        drop(tail);

        let dir = tempfile::tempdir().unwrap();
        let options = checkpoint_options(&dir.path().join("checkpoint.sqlite"), &tls, binding);
        let keys = checkpoint_keys();
        let checkpoint = ConsumerCheckpointStore::provision(options.clone(), keys.clone())
            .await
            .unwrap();
        let mut consumer = DurableConfigConsumer::new(remote(), checkpoint, Duration::from_secs(3))
            .await
            .unwrap();
        let mut runtime = NumericRuntime::default();
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        assert_eq!(
            consumer.replace_snapshot().await.unwrap(),
            ConfigAcceptanceOutcome::Accepted
        );
        assert_eq!(
            consumer.replace_snapshot().await.unwrap(),
            ConfigAcceptanceOutcome::AlreadyAccepted
        );
        consumer.apply_observed(&mut runtime).await.unwrap();
        assert_eq!(
            runtime.actual,
            Some((tx, ConfigVersion::new(1), config.clone()))
        );
        assert_eq!(runtime.applies, 1);
        consumer.shutdown().await.unwrap();

        let checkpoint = ConsumerCheckpointStore::reopen(options, keys)
            .await
            .unwrap();
        let mut consumer = DurableConfigConsumer::new(remote(), checkpoint, Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(
            consumer.status().phase,
            ConfigConsumerPhase::ReadbackRequired
        );
        consumer.reconcile_runtime(&mut runtime).await.unwrap();
        assert_eq!(consumer.status().phase, ConfigConsumerPhase::Applied);
        assert_eq!(
            consumer.replace_snapshot().await.unwrap(),
            ConfigAcceptanceOutcome::AlreadyAccepted
        );
        assert_eq!(runtime.applies, 1);
        assert_eq!(runtime.actual, Some((tx, ConfigVersion::new(1), config)));
        consumer.shutdown().await.unwrap();
        server.shutdown().await;
    }
}
