use super::*;
use crate::audit_authority::{AuditLedgerLimits, AuditPrivacyKey};
use crate::{
    AuditKey, ConfigConsensusClock, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, RetainedConfigBinding, RetainedConfigDurability,
    RetainedConfigOptions,
};
use async_trait::async_trait;
use opc_types::Timestamp;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Mutex;
use tokio::sync::Notify;

#[derive(Debug)]
struct TestClock(AtomicI64);

impl ConfigConsensusClock for TestClock {
    fn now_utc(&self) -> Timestamp {
        Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::Acquire)).unwrap(),
        )
    }
}

#[derive(Default)]
struct LoadGate {
    entered: Notify,
    release: Notify,
    active: AtomicUsize,
    dropped: AtomicUsize,
}

struct Loading(Arc<LoadGate>);

impl Drop for Loading {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
        self.0.dropped.fetch_add(1, Ordering::AcqRel);
    }
}

#[derive(Default)]
struct Checkpoints {
    value: Mutex<Option<AuditCheckpoint>>,
    next_load: Mutex<Option<Arc<LoadGate>>>,
}

#[async_trait]
impl AuditCheckpointPort for Checkpoints {
    async fn load(
        &self,
        _: ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        let gate = self.next_load.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.active.fetch_add(1, Ordering::AcqRel);
            let _loading = Loading(gate.clone());
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        Ok(self.value.lock().unwrap().clone())
    }

    async fn compare_advance(
        &self,
        _: ConfigConsensusIdentity,
        expected: Option<AuditCheckpoint>,
        next: AuditCheckpoint,
    ) -> Result<AuditCheckpointAdvance, AuditAuthorityError> {
        let mut current = self.value.lock().unwrap();
        if *current != expected
            || current
                .as_ref()
                .is_some_and(|old| old.sequence() >= next.sequence())
        {
            return Ok(AuditCheckpointAdvance::Conflict);
        }
        *current = Some(next);
        Ok(AuditCheckpointAdvance::Applied)
    }
}

struct Fixture {
    store: ConsensusConfigStore,
    clock: Arc<TestClock>,
    external: Arc<Checkpoints>,
    identity: ConfigConsensusIdentity,
    caller: AuditCaller,
    _dir: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(TestClock(AtomicI64::new(1_900_000_000)));
        let external = Arc::new(Checkpoints::default());
        let node = ConsensusNodeId::new(1).unwrap();
        let identity = ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::new("recipient-expiry-tests").unwrap(),
            ConfigConsensusConfigurationId::from_bytes([0x42; 32]),
            ConfigConsensusConfigurationEpoch::new(1).unwrap(),
        );
        let topology =
            ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).unwrap();
        let options = RetainedConfigOptions::new(
            dir.path().join("authority.sqlite"),
            RetainedConfigBinding::new(topology.clone(), [1; 32], [0x61; 32]).unwrap(),
            RetainedConfigDurability::Ephemeral,
            64 * 1024 * 1024,
            Duration::from_secs(30),
        )
        .unwrap();
        let backend =
            SqliteBackend::provision_config_authority(options, AuditKey::new([0x55; 32]).unwrap())
                .await
                .unwrap();
        let keys = AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x71; 32]).unwrap()]).unwrap();
        let store = ConsensusConfigStore::open_internal(
            topology,
            backend,
            dir.path().join("snapshots"),
            BTreeMap::new(),
            clock.clone(),
            DEFAULT_CONFIG_CONSENSUS_OPERATION_TIMEOUT,
            None,
            Some(Arc::new(
                AuditContinuityPolicy::new(keys, external.clone(), 1, 1).unwrap(),
            )),
            None,
        )
        .await
        .unwrap();
        store.initialize_cluster().await.unwrap();
        let privacy = AuditPrivacyKey::new([0xA9; 32]).unwrap();
        store
            .initialize_audit_authority(&privacy, AuditLedgerLimits::new(24, 8).unwrap())
            .await
            .unwrap();
        let caller =
            AuditCaller::project(&privacy, "synthetic-tenant", "synthetic-recipient").unwrap();
        Self {
            store,
            clock,
            external,
            identity,
            caller,
            _dir: dir,
        }
    }

    async fn begin(&self) -> AuditRecipientExportSession {
        let client = AuditRecipientClient::new(self.identity, self.caller);
        let request =
            AuditRecipientVerificationRequest::decode(&client.request().encode().unwrap()).unwrap();
        self.store
            .begin_recipient_audit_export(self.caller, 0, Duration::from_secs(1), &request)
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn recipient_online_expiry_after_real_checkpoint_wait_refuses() {
    let f = Fixture::new().await;
    let mut session = f.begin().await;
    // The authority binding keeps this store-clock regression independent of
    // client wall time. Integration tests cover the client's accept_opened path.
    let binding = session.binding().clone();
    let issued_at = binding.manifest().body.issued_at;
    let expires_at = binding.manifest().body.expires_at;
    assert_eq!(issued_at, 1_900_000_000);
    assert_eq!(expires_at, issued_at + 1);
    let page = session.page(&binding, f.caller, None, 1).unwrap();
    assert!(page.next_cursor().is_none());
    session
        .accept_received_page(&binding, f.caller, &page.encode().unwrap())
        .unwrap();

    let gate = Arc::new(LoadGate::default());
    *f.external.next_load.lock().unwrap() = Some(gate.clone());
    let mut pending = Box::pin(session.finish(&binding, f.caller));
    tokio::select! {
        entered = tokio::time::timeout(Duration::from_secs(10), gate.entered.notified()) => {
            entered.unwrap();
            assert_eq!(gate.active.load(Ordering::Acquire), 1);
            assert_eq!(gate.dropped.load(Ordering::Acquire), 0);
        }
        _ = &mut pending => panic!("finish escaped the real independent provider gate"),
    }
    // Keep time fixed through setup and page upload, regardless of wall time.
    // Expire exactly at the original boundary, only after the provider is pending.
    assert_eq!(f.store.recipient_audit_now(), issued_at);
    f.clock.0.store(expires_at, Ordering::Release);
    gate.release.notify_one();
    assert!(
        matches!(pending.await, Err(AuditAuthorityError::Expired)),
        "POST_WAIT_FIXED_EXPIRY"
    );
    assert_eq!(gate.active.load(Ordering::Acquire), 0);
    assert_eq!(gate.dropped.load(Ordering::Acquire), 1);
    drop(f.begin().await);
    f.store.shutdown().await.unwrap();
}

#[tokio::test]
async fn recipient_online_fixed_expiry_refuses_page_and_finish() {
    let f = Fixture::new().await;
    let mut session = f.begin().await;
    // Bind directly so the client's wall clock cannot expire the test setup.
    let binding = session.binding().clone();
    let issued_at = binding.manifest().body.issued_at;
    let expires_at = binding.manifest().body.expires_at;
    assert_eq!(issued_at, 1_900_000_000);
    assert_eq!(expires_at, issued_at + 1);
    assert_eq!(binding.manifest().body.row_count, 0);
    let page = session.page(&binding, f.caller, None, 1).unwrap();
    assert!(page.next_cursor().is_none());
    session
        .accept_received_page(&binding, f.caller, &page.encode().unwrap())
        .unwrap();

    assert_eq!(f.store.recipient_audit_now(), issued_at);
    f.clock.0.store(expires_at, Ordering::Release);
    assert!(
        matches!(
            session.page(&binding, f.caller, None, 1),
            Err(AuditAuthorityError::Expired)
        ),
        "FIXED_PAGE_EXPIRY"
    );
    assert!(
        matches!(
            session.finish(&binding, f.caller).await,
            Err(AuditAuthorityError::Expired)
        ),
        "FIXED_SESSION_EXPIRY"
    );
    drop(f.begin().await);
    f.store.shutdown().await.unwrap();
}
