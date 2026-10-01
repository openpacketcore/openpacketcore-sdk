//! Local duplex regression for an accepted legacy confirmed commit. The
//! in-memory store preserves real ConfigBus ordering but proves no durability.

use super::*;
use opc_config_bus::{CommitWrite, ManagedDatastore, StoreError};
use opc_config_model::{IdempotencyKey, RollbackTarget};
use opc_types::TxId;

const WAIT: Duration = Duration::from_secs(10);

#[derive(Default)]
struct PausedConfirmedStore {
    inner: MockManagedDatastore<DemoConfig>,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    published: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl ManagedDatastore<DemoConfig> for PausedConfirmedStore {
    async fn load_latest(&self) -> Result<Option<StoredConfig<DemoConfig>>, StoreError> {
        self.inner.load_latest().await
    }

    async fn load_rollback(
        &self,
        target: RollbackTarget,
    ) -> Result<StoredConfig<DemoConfig>, StoreError> {
        self.inner.load_rollback(target).await
    }

    async fn load_by_idempotency_key(
        &self,
        key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<DemoConfig>>, StoreError> {
        self.inner.load_by_idempotency_key(key).await
    }

    async fn load_by_request_id(
        &self,
        request_id: RequestId,
    ) -> Result<Option<StoredConfig<DemoConfig>>, StoreError> {
        self.inner.load_by_request_id(request_id).await
    }

    async fn append_commit_write(&self, commit: CommitWrite<DemoConfig>) -> Result<(), StoreError> {
        if commit.record().confirmed_deadline.is_some() {
            // The real worker has accepted the request independently of the
            // RPC response future. Its append remains pending through kill.
            self.entered.notify_one();
            self.release.notified().await;
        }
        self.inner.append_commit_write(commit).await
    }

    async fn clear_recovery_required(&self, tx_id: TxId) -> Result<(), StoreError> {
        self.inner.clear_recovery_required(tx_id).await?;
        self.published.notify_one();
        Ok(())
    }
}

type Server = ReadOnlyNetconfServer<DemoConfig, GeneratedEditBinding, FixedPolicy, CapturingAudit>;

struct Client {
    stream: tokio::io::DuplexStream,
    runner: tokio::task::JoinHandle<
        Result<crate::session::SessionResult, crate::session::SessionError>,
    >,
}

impl Client {
    async fn start(server: Arc<Server>, sessions: SessionRegistry, id: u64) -> Self {
        let (mut stream, client) = tokio::io::duplex(8192);
        let runner = tokio::spawn(async move {
            crate::session::run_read_only_session_with_registry(
                &server,
                &principal(),
                &mut stream,
                SessionConfig::default(),
                id,
                &sessions,
            )
            .await
        });
        let mut client = Self {
            stream: client,
            runner,
        };
        assert!(client.reply().await.contains(CONFIRMED_COMMIT_1_1));
        client.send(&format!(r#"<hello xmlns="{NETCONF_BASE_NS}"><capabilities><capability>{NETCONF_BASE_1_0}</capability></capabilities></hello>"#)).await;
        client
    }

    async fn send(&mut self, xml: &str) {
        self.stream
            .write_all(&base10::encode_message(xml.as_bytes(), &MgmtLimits::default()).unwrap())
            .await
            .unwrap();
    }

    async fn reply(&mut self) -> String {
        String::from_utf8(
            tokio::time::timeout(WAIT, read_base10_frame(&mut self.stream))
                .await
                .expect("duplex frame"),
        )
        .unwrap()
    }

    async fn rpc(&mut self, xml: &str) -> String {
        self.send(xml).await;
        self.reply().await
    }

    async fn join(mut self) -> bool {
        let joined = tokio::time::timeout(WAIT, &mut self.runner).await;
        if joined.is_err() {
            self.runner.abort();
            let _ = self.runner.await;
        }
        matches!(joined, Ok(Ok(Ok(_))))
    }
}

#[tokio::test]
async fn legacy_kill_preserves_accepted_confirmed_commit_exit_rollback() {
    let store = Arc::new(PausedConfirmedStore::default());
    let initial = DemoConfig {
        hostname: "amf-1".into(),
        secret: "synthetic-secret".into(),
    };
    store
        .inner
        .seed(StoredConfig::new(
            TxId::new(),
            ConfigVersion::new(1),
            principal(),
            RequestSource::Northbound,
            initial.clone(),
        ))
        .await;
    let bus = Arc::new(
        ConfigBus::restore_or_new_dev_only(initial, store.clone())
            .await
            .unwrap(),
    );
    let server = Arc::new(
        ReadOnlyNetconfServer::new(
            GeneratedEditBinding {
                bus: bus.clone(),
                startup: None,
            },
            FixedPolicy(policy_allow_system_with_secret_writes()),
            CapturingAudit::default(),
            TransportType::NetconfTls,
        )
        .unwrap(),
    );
    let sessions = SessionRegistry::new();
    let mut victim = Client::start(server.clone(), sessions.clone(), 601).await;
    let mut controller = Client::start(server.clone(), sessions, 602).await;
    let staged = victim
        .rpc(&edit_config_rpc_to(
            "candidate",
            r#"<sys:system xmlns:sys="urn:opc:demo"><sys:hostname>amf-2</sys:hostname></sys:system>"#,
            "merge",
        ))
        .await;
    assert!(staged.contains("<ok/>"), "candidate setup: {staged}");
    victim.send(&confirmed_commit_rpc(30)).await;
    tokio::time::timeout(WAIT, store.entered.notified())
        .await
        .expect("accepted confirmed commit reached append");
    let before = bus.current_snapshot().version == ConfigVersion::new(1)
        && server
            .confirmed_commit
            .lock()
            .unwrap()
            .active(Instant::now())
            .is_none();
    let killed = controller.rpc(&kill_session_rpc(601)).await;
    store.release.notify_one();
    // Observe the independent worker's publication even if a faulty runner
    // already returned without recording the owner or requesting rollback.
    tokio::time::timeout(WAIT, store.published.notified())
        .await
        .expect("accepted write published");
    let finished = victim.join().await;
    let history = store.inner.history().await;
    let snapshot = bus.current_snapshot();
    let cleared = server
        .confirmed_commit
        .lock()
        .unwrap()
        .active(Instant::now())
        .is_none();
    let closed = controller.rpc(&close_session_rpc()).await.contains("<ok/>");
    let controller_finished = controller.join().await;
    eprintln!(
        "LEGACY_CONFIRMED_KILL_OBSERVED before={before} acknowledged={} finished={finished} history_rows={} version={} hostname={} cleared={cleared} closed={closed} controller_finished={controller_finished}",
        killed.contains("<ok/>"), history.len(), snapshot.version.get(), snapshot.config.hostname,
    );
    assert!(
        closed && controller_finished,
        "LEGACY_CONFIRMED_KILL_CLEANUP"
    );
    assert!(
        before
            && killed.contains("<ok/>")
            && finished
            && history.len() == 3
            && history[1].config.hostname == "amf-2"
            && history[2].config.hostname == "amf-1"
            && history[2].confirmed_deadline.is_none()
            && !history[2].recovery_required
            && snapshot.version == ConfigVersion::new(3)
            && snapshot.config.hostname == "amf-1"
            && cleared,
        "LEGACY_CONFIRMED_KILL_PRESERVES_EXIT_ROLLBACK"
    );
}
