use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::{FutureExt, StreamExt};
use opc_config_bus::{
    AuthorityMode, CommitWrite, CommittedRevisionSource, ConfigBus, ConfigRevisionCursor,
    DriftState, ManagedDatastore, MockManagedDatastore, StoreError, StoreErrorCode, StoredConfig,
    MAX_CONFIG_HISTORY_PAGE_ENTRIES,
};
use opc_config_model::{CommitErrorCode, IdempotencyKey, OpcConfig, RequestId, RollbackTarget};
use opc_types::{ConfigVersion, TxId};

mod config_bus_common;
use config_bus_common::*;

#[derive(Clone)]
struct AppliedStore<C: OpcConfig> {
    inner: Arc<MockManagedDatastore<C>>,
    page_error: Option<StoreError>,
    clear_error: Option<StoreError>,
}

impl<C: OpcConfig> AppliedStore<C> {
    fn new(inner: Arc<MockManagedDatastore<C>>) -> Self {
        Self {
            inner,
            page_error: None,
            clear_error: None,
        }
    }

    fn compacted(inner: Arc<MockManagedDatastore<C>>) -> Self {
        Self {
            inner,
            page_error: Some(StoreError::history_compacted(
                "requested committed config history is no longer retained",
            )),
            clear_error: None,
        }
    }

    fn clear_fails(inner: Arc<MockManagedDatastore<C>>) -> Self {
        Self {
            inner,
            page_error: None,
            clear_error: Some(StoreError::unavailable("recovery marker clear failed")),
        }
    }
}

#[async_trait]
impl<C: OpcConfig> ManagedDatastore<C> for AppliedStore<C> {
    async fn load_latest(&self) -> Result<Option<StoredConfig<C>>, StoreError> {
        self.inner.load_latest().await
    }

    async fn load_committed_latest(&self) -> Result<Option<StoredConfig<C>>, StoreError> {
        self.inner.load_committed_latest().await
    }

    async fn load_since(
        &self,
        after: ConfigVersion,
        limit: usize,
    ) -> Result<Vec<StoredConfig<C>>, StoreError> {
        if let Some(error) = &self.page_error {
            return Err(error.clone());
        }
        self.inner.load_since(after, limit).await
    }

    async fn wait_for_committed_change(&self, after: ConfigVersion) -> Result<(), StoreError> {
        self.inner.wait_for_committed_change(after).await
    }

    async fn load_rollback(&self, target: RollbackTarget) -> Result<StoredConfig<C>, StoreError> {
        self.inner.load_rollback(target).await
    }

    async fn load_by_idempotency_key(
        &self,
        key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<C>>, StoreError> {
        self.inner.load_by_idempotency_key(key).await
    }

    async fn load_by_request_id(
        &self,
        request_id: RequestId,
    ) -> Result<Option<StoredConfig<C>>, StoreError> {
        self.inner.load_by_request_id(request_id).await
    }

    async fn append_commit_write(&self, write: CommitWrite<C>) -> Result<(), StoreError> {
        self.inner.append_commit_write(write).await
    }

    async fn clear_recovery_required(&self, tx_id: TxId) -> Result<(), StoreError> {
        if let Some(error) = &self.clear_error {
            return Err(error.clone());
        }
        self.inner.clear_recovery_required(tx_id).await
    }

    async fn mark_confirmed(&self, tx_id: TxId) -> Result<(), StoreError> {
        self.inner.mark_confirmed(tx_id).await
    }
}

impl<C: OpcConfig> CommittedRevisionSource<C> for AppliedStore<C> {}

async fn commit(bus: &ConfigBus<TestConfig>, name: &str) {
    bus.submit(
        commit_request(name, Instant::now() + Duration::from_secs(2))
            .with_base_version(bus.version()),
    )
    .await
    .expect("commit succeeds");
}

async fn authoritative_bus() -> (ConfigBus<TestConfig>, Arc<MockManagedDatastore<TestConfig>>) {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("genesis"), Arc::clone(&store))
        .await
        .expect("committed genesis");
    (bus, store)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_then_tail_has_no_gap_or_overlap() {
    let (bus, _) = authoritative_bus().await;
    commit(&bus, "v1").await;
    commit(&bus, "v2").await;

    let recovery = bus
        .recover_from(None)
        .await
        .expect("recover committed head");
    assert_eq!(ConfigVersion::new(2), recovery.snapshot().version);
    assert_eq!("v2", recovery.snapshot().config.name);
    let (_, mut tail) = recovery.into_parts();

    commit(&bus, "v3").await;
    commit(&bus, "v4").await;

    let third = tail
        .next()
        .await
        .expect("third item")
        .expect("third revision");
    let fourth = tail
        .next()
        .await
        .expect("fourth item")
        .expect("fourth revision");
    assert_eq!(
        (ConfigVersion::new(3), "v3"),
        (third.version, third.config.name.as_str())
    );
    assert_eq!(
        (ConfigVersion::new(4), "v4"),
        (fourth.version, fourth.config.name.as_str())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn durable_page_handoff_is_strict_across_more_than_one_page() {
    let (bus, _) = authoritative_bus().await;
    let count = MAX_CONFIG_HISTORY_PAGE_ENTRIES + 7;
    for revision in 1..=count {
        commit(&bus, &format!("v{revision}")).await;
    }

    let mut watch = bus
        .watch_committed(ConfigVersion::INITIAL)
        .await
        .expect("watch complete history");
    for revision in 1..=count {
        let entry = watch
            .next()
            .await
            .expect("history item")
            .expect("valid history item");
        assert_eq!(ConfigVersion::new(revision as u64), entry.version);
        assert_eq!(format!("v{revision}"), entry.config.name);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_before_head_closes_the_empty_page_race() {
    let (bus, _) = authoritative_bus().await;
    let mut watch = bus
        .watch_committed(ConfigVersion::INITIAL)
        .await
        .expect("watch at head");
    let mut next = Box::pin(watch.next());
    tokio::task::yield_now().await;
    assert!(next.as_mut().now_or_never().is_none());

    commit(&bus, "v1").await;
    let entry = next
        .await
        .expect("first item")
        .expect("first committed revision");
    assert_eq!(ConfigVersion::new(1), entry.version);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fenced_append_is_hidden_until_clear_and_clear_wakes_the_watch() {
    let (bus, store) = authoritative_bus().await;
    let genesis = store.latest().await.expect("durable genesis");
    let mut watch = bus
        .watch_committed(ConfigVersion::INITIAL)
        .await
        .expect("watch cleared head");
    let mut next = Box::pin(watch.next());
    tokio::task::yield_now().await;
    assert!(next.as_mut().now_or_never().is_none());

    let tx_id = TxId::new();
    let mut fenced = StoredConfig::new(
        tx_id,
        ConfigVersion::new(1),
        principal(),
        opc_config_model::RequestSource::Internal,
        TestConfig::new("pending-publication"),
    );
    fenced.parent_tx_id = Some(genesis.tx_id);
    fenced.recovery_required = true;
    fenced.confirmed_deadline = Some(opc_types::Timestamp::now_utc());
    store
        .append_commit_write(CommitWrite::new(fenced))
        .await
        .expect("append locally applied fenced revision");

    assert_eq!(
        ConfigVersion::INITIAL,
        store
            .load_committed_latest()
            .await
            .expect("publish-safe head")
            .expect("cleared genesis")
            .version
    );
    assert!(store
        .load_since(ConfigVersion::INITIAL, 1)
        .await
        .expect("publish-safe page")
        .is_empty());
    tokio::task::yield_now().await;
    assert!(next.as_mut().now_or_never().is_none());

    store
        .clear_recovery_required(tx_id)
        .await
        .expect("clear publication fence");
    let entry = next
        .await
        .expect("clear wakes watch")
        .expect("cleared revision");
    assert_eq!(ConfigVersion::new(1), entry.version);
    assert_eq!("pending-publication", entry.config.name);
    assert!(store
        .load_committed_latest()
        .await
        .expect("publish-safe head")
        .expect("cleared revision")
        .confirmed_deadline
        .is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clear_failure_leaves_the_fenced_tail_permanently_invisible() {
    let inner = Arc::new(MockManagedDatastore::new());
    inner
        .seed(StoredConfig::new(
            TxId::new(),
            ConfigVersion::INITIAL,
            principal(),
            opc_config_model::RequestSource::StartupRecovery,
            TestConfig::new("genesis"),
        ))
        .await;
    let bus = ConfigBus::restore_or_new_dev_only(
        TestConfig::new("fallback"),
        AppliedStore::clear_fails(Arc::clone(&inner)),
    )
    .await
    .expect("restore cleared prefix");
    let mut watch = bus
        .watch_committed(ConfigVersion::INITIAL)
        .await
        .expect("watch cleared prefix");
    let mut next = Box::pin(watch.next());
    tokio::task::yield_now().await;

    commit(&bus, "fenced-tail").await;
    assert_eq!(DriftState::RecoveryRequired, bus.drift_state());
    assert_eq!(ConfigVersion::new(1), bus.version());
    assert_eq!(
        ConfigVersion::INITIAL,
        inner
            .load_committed_latest()
            .await
            .expect("publish-safe head")
            .expect("cleared genesis")
            .version
    );
    tokio::task::yield_now().await;
    assert!(next.as_mut().now_or_never().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn known_or_watch_cursor_ahead_of_local_applied_head_fails_typed() {
    let (bus, _) = authoritative_bus().await;
    let ahead = ConfigVersion::new(1);

    let recovery_error = bus
        .recover_from(Some(ahead))
        .await
        .expect_err("recovery cannot move backward");
    assert_eq!(StoreErrorCode::HistoryCursorAhead, recovery_error.code);

    let watch_error = bus
        .watch_committed(ahead)
        .await
        .err()
        .expect("watch cannot wait from an uncommitted future cursor");
    assert_eq!(StoreErrorCode::HistoryCursorAhead, watch_error.code);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_uncommitted_store_cannot_authorize_recovery_or_shadow_restore() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("bootstrap-only"), Arc::clone(&store))
        .await
        .expect("bootstrap bus");
    assert_eq!(
        StoreErrorCode::NotFound,
        bus.recover_from(None)
            .await
            .expect_err("bootstrap snapshot is not a committed head")
            .code
    );
    assert_eq!(
        StoreErrorCode::NotFound,
        ConfigBus::restore_shadow(AppliedStore::new(store))
            .await
            .err()
            .expect("shadow requires committed provenance")
            .code
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadow_serves_only_its_local_applied_history_and_rejects_writes() {
    let (leader, leader_store) = authoritative_bus().await;
    commit(&leader, "v1").await;
    commit(&leader, "v2").await;

    let follower_store = Arc::new(MockManagedDatastore::new());
    for record in leader_store.history().await {
        follower_store.seed(record).await;
    }
    let shadow = ConfigBus::restore_shadow(AppliedStore::new(Arc::clone(&follower_store)))
        .await
        .expect("restore follower-local committed head");
    assert_eq!(AuthorityMode::Shadow, shadow.authority_mode());
    assert_eq!(ConfigVersion::new(2), shadow.version());

    let before = follower_store.history().await.len();
    let error = shadow
        .submit(
            commit_request("forbidden", Instant::now() + Duration::from_secs(2))
                .with_base_version(shadow.version()),
        )
        .await
        .expect_err("shadow mutation rejected");
    assert_eq!(CommitErrorCode::AdmissionRejected, error.code);
    assert_eq!(before, follower_store.history().await.len());

    let mut follower_watch = shadow
        .watch_committed(ConfigVersion::new(2))
        .await
        .expect("follower watch");
    let mut next = Box::pin(follower_watch.next());
    tokio::task::yield_now().await;
    assert!(next.as_mut().now_or_never().is_none());

    commit(&leader, "v3").await;
    tokio::task::yield_now().await;
    assert!(next.as_mut().now_or_never().is_none());

    let revision_three = leader_store
        .history()
        .await
        .into_iter()
        .find(|record| record.version == ConfigVersion::new(3))
        .expect("leader revision three");
    follower_store.seed(revision_three).await;
    let entry = next
        .await
        .expect("follower item")
        .expect("locally applied follower revision");
    assert_eq!(ConfigVersion::new(3), entry.version);
    assert_eq!("v3", entry.config.name);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_watch_does_not_delay_commits_or_an_independent_consumer() {
    let (bus, _) = authoritative_bus().await;
    let _stalled = bus
        .watch_committed(ConfigVersion::INITIAL)
        .await
        .expect("stalled watch");

    for revision in 1..=8 {
        commit(&bus, &format!("v{revision}")).await;
    }
    let page = bus
        .load_committed_page(ConfigRevisionCursor::after(ConfigVersion::INITIAL), 8)
        .await
        .expect("independent bounded consumer");
    assert_eq!(8, page.len());
    assert_eq!(ConfigVersion::new(8), bus.version());
}

#[tokio::test]
async fn over_contract_page_and_gapped_history_fail_closed() {
    let (bus, store) = authoritative_bus().await;
    let page_error = bus
        .load_committed_page(
            ConfigRevisionCursor::after(ConfigVersion::INITIAL),
            MAX_CONFIG_HISTORY_PAGE_ENTRIES + 1,
        )
        .await
        .expect_err("oversized page rejected");
    assert_eq!(StoreErrorCode::HistoryPageTooLarge, page_error.code);

    store
        .seed(StoredConfig::new(
            TxId::new(),
            ConfigVersion::new(2),
            principal(),
            opc_config_model::RequestSource::Internal,
            TestConfig::new("gap"),
        ))
        .await;
    let sequence_error = bus
        .watch_committed(ConfigVersion::INITIAL)
        .await
        .err()
        .expect("gap rejected before stream escapes");
    assert_eq!(StoreErrorCode::InvalidHistorySequence, sequence_error.code);
}

#[tokio::test]
async fn compacted_history_requires_typed_snapshot_recovery() {
    let (_, store) = authoritative_bus().await;
    let shadow = ConfigBus::restore_shadow(AppliedStore::compacted(store))
        .await
        .expect("restore retained committed head");
    let error = shadow
        .watch_committed(ConfigVersion::INITIAL)
        .await
        .err()
        .expect("stale cursor must not silently skip compacted history");
    assert_eq!(StoreErrorCode::HistoryCompacted, error.code);
}

#[test]
fn deserialized_history_pages_revalidate_sequence_and_cursor() {
    let page = opc_config_bus::ConfigHistoryPage::try_new(
        ConfigRevisionCursor::after(ConfigVersion::INITIAL),
        vec![opc_config_bus::CommittedConfigHistoryEntry {
            tx_id: TxId::new(),
            version: ConfigVersion::new(1),
            config: (),
        }],
    )
    .expect("valid page");

    let mut mismatched_cursor = serde_json::to_value(&page).expect("serialize page");
    mismatched_cursor["next_cursor"]["after"] = serde_json::json!(0);
    assert!(
        serde_json::from_value::<opc_config_bus::ConfigHistoryPage<()>>(mismatched_cursor).is_err()
    );

    let mut gapped = serde_json::to_value(&page).expect("serialize page");
    gapped["entries"][0]["version"] = serde_json::json!(2);
    gapped["next_cursor"]["after"] = serde_json::json!(2);
    assert!(serde_json::from_value::<opc_config_bus::ConfigHistoryPage<()>>(gapped).is_err());

    let mut oversized = serde_json::to_value(&page).expect("serialize page");
    let entry = oversized["entries"][0].clone();
    oversized["entries"] =
        serde_json::Value::Array(vec![entry; MAX_CONFIG_HISTORY_PAGE_ENTRIES + 1]);
    assert!(serde_json::from_value::<opc_config_bus::ConfigHistoryPage<()>>(oversized).is_err());
}

#[test]
fn committed_debug_surfaces_never_render_config_payloads() {
    let revision = opc_config_bus::CommittedConfigHistoryEntry {
        tx_id: TxId::new(),
        version: ConfigVersion::new(7),
        config: TestConfig::new("super-secret-hostname"),
    };
    let rendered = format!("{revision:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("super-secret-hostname"));
}
