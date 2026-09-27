//! Real retained authority and independent checkpoint fixtures. The application
//! authentication boundary supplies `caller()` separately from every wire value.
//! These tests qualify the SDK protocol, not a production TLS/server deployment.
use super::*;
use std::sync::atomic::AtomicUsize;
use tokio::sync::Notify;

#[derive(Default)]
struct LoadGate {
    entered: Notify,
    release: Notify,
    active: AtomicUsize,
}

struct Loading(Arc<LoadGate>);
impl Drop for Loading {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Default)]
struct Checkpoints {
    inner: ExternalCheckpointFixture,
    writes: AtomicUsize,
    next_load: StdMutex<Option<Arc<LoadGate>>>,
}

#[async_trait]
impl AuditCheckpointPort for Checkpoints {
    async fn load(
        &self,
        identity: ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        let gate = self.next_load.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.active.fetch_add(1, Ordering::AcqRel);
            let _loading = Loading(gate.clone());
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        self.inner.load(identity).await
    }

    async fn compare_advance(
        &self,
        identity: ConfigConsensusIdentity,
        expected: Option<AuditCheckpoint>,
        next: AuditCheckpoint,
    ) -> Result<AuditCheckpointAdvance, AuditAuthorityError> {
        self.writes.fetch_add(1, Ordering::AcqRel);
        self.inner.compare_advance(identity, expected, next).await
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    store: ConsensusConfigStore,
    external: Arc<Checkpoints>,
}

impl Fixture {
    async fn new(exports: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let external = Arc::new(Checkpoints::default());
        let store = open_store(dir.path(), external.clone(), &[1, 2], exports, true).await;
        store.initialize_cluster().await.unwrap();
        store
            .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(24, 8).unwrap())
            .await
            .unwrap();
        Self {
            dir,
            store,
            external,
        }
    }

    async fn observe(&self, request: u8) {
        let handle = self
            .store
            .prepare_audit_observation(
                &privacy(),
                &source_event(request, ManagementAuditOutcomeCode::Denied),
                Duration::from_secs(3),
            )
            .unwrap();
        let receipt = applied(self.store.admit_audit_operation(&handle, caller()).await);
        assert!(receipt.terminal_recorded());
        assert_eq!(
            self.store
                .lookup_audit_operation(&handle, caller())
                .await
                .unwrap(),
            Some(receipt)
        );
    }

    fn ledger_bytes(&self) -> (Vec<u8>, Vec<u8>) {
        let conn = rusqlite::Connection::open(self.dir.path().join("authority.sqlite")).unwrap();
        conn.query_row(
            "SELECT state_json, state_hmac FROM config_raft_management_audit WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
    }

    fn checkpoint(&self) -> AuditCheckpoint {
        self.external.inner.value.lock().unwrap().clone().unwrap()
    }

    async fn begin(&self, lifetime: u64) -> (AuditRecipientClient, AuditRecipientExportSession) {
        begin(&self.store, 0, lifetime).await
    }
}

async fn open_store(
    dir: &std::path::Path,
    external: Arc<Checkpoints>,
    epochs: &[u64],
    exports: usize,
    fresh: bool,
) -> ConsensusConfigStore {
    let options = retained_options(&dir.join("authority.sqlite"), topology(), 1);
    let backend = if fresh {
        SqliteBackend::provision_config_authority(options, audit_key()).await
    } else {
        SqliteBackend::reopen_config_authority(options, audit_key()).await
    }
    .unwrap();
    ConsensusConfigStore::open_with_audit_continuity(
        topology(),
        backend,
        dir.join("snapshots"),
        BTreeMap::new(),
        AuditContinuityPolicy::new(keys(epochs), external, epochs[0], exports).unwrap(),
    )
    .await
    .unwrap()
}

async fn begin(
    store: &ConsensusConfigStore,
    floor: u64,
    lifetime: u64,
) -> (AuditRecipientClient, AuditRecipientExportSession) {
    // The client has only public protocol inputs. No AuditKeyRing enters its API.
    let mut client = AuditRecipientClient::new(topology().identity(), caller());
    let request =
        AuditRecipientVerificationRequest::decode(&client.request().encode().unwrap()).unwrap();
    let session = store
        .begin_recipient_audit_export(caller(), floor, Duration::from_secs(lifetime), &request)
        .await
        .unwrap();
    client
        .accept_opened(&session.binding().encode().unwrap())
        .unwrap();
    (client, session)
}

fn received_pages(
    session: &AuditRecipientExportSession,
    binding: &AuditRecipientSessionBinding,
) -> Vec<Vec<u8>> {
    let mut pages = Vec::new();
    let mut cursor = None;
    loop {
        let bytes = session
            .page(binding, caller(), cursor.as_ref(), 1)
            .unwrap()
            .encode()
            .unwrap();
        // This decoder makes no authenticity claim. The actual received bytes
        // are sent back, not replaced by a page regenerated at the authority.
        let received = AuditExportPage::decode(&bytes).unwrap();
        cursor = received.next_cursor().cloned();
        pages.push(bytes);
        if cursor.is_none() {
            break;
        }
    }
    pages
}

fn upload(
    session: &mut AuditRecipientExportSession,
    binding: &AuditRecipientSessionBinding,
    pages: &[Vec<u8>],
) {
    for page in pages {
        session
            .accept_received_page(binding, caller(), page)
            .unwrap();
    }
}

#[tokio::test]
async fn recipient_online_native_rotation_readonly_completion_and_reopen() {
    let f = Fixture::new(1).await;
    f.observe(101).await;
    let transition = f.store.prepare_audit_key_transition(2).await.unwrap();
    f.store
        .activate_audit_key_transition(&transition)
        .await
        .unwrap();
    f.observe(102).await;
    let ledger_before = f.ledger_bytes();
    let external_before = f.checkpoint();
    let writes = f.external.writes.load(Ordering::Acquire);
    let (client, mut session) = f.begin(60).await;
    let binding = client.binding().unwrap().clone();
    let pages = received_pages(&session, &binding);
    assert_eq!(pages.len(), 3, "NATIVE_CROSS_EPOCH_RANGE");
    upload(&mut session, &binding, &pages);
    let completed = session.finish(&binding, caller()).await.unwrap();
    let report = client
        .accept_report(&completed.report().encode().unwrap())
        .unwrap();
    assert_eq!(report.manifest(), binding.manifest());
    assert_eq!((report.frozen_floor(), report.frozen_sequence()), (0, 3));
    assert_eq!(
        report.checkpoint_at_freeze(),
        &external_before,
        "FROZEN_PREFIX_COVERAGE"
    );
    assert_eq!(report.checkpoint_at_freeze().sequence(), 0);
    assert_eq!(report.checkpoint_at_finish(), &external_before);
    assert_eq!(f.ledger_bytes(), ledger_before, "VERIFICATION_IS_READ_ONLY");
    assert_eq!(f.external.writes.load(Ordering::Acquire), writes);
    assert_eq!(f.checkpoint(), external_before);
    assert!(
        f.store.retain_audit_history_through(3).await.is_err(),
        "REPORT_IS_NOT_ACKNOWLEDGEMENT"
    );
    let another = AuditRecipientClient::new(topology().identity(), caller());
    assert!(
        matches!(
            f.store
                .begin_recipient_audit_export(
                    caller(),
                    0,
                    Duration::from_secs(60),
                    another.request(),
                )
                .await,
            Err(AuditAuthorityError::Full)
        ),
        "COMPLETION_RETAINS_EXPORT_OWNER"
    );
    drop(completed);
    let (_, released) = f.begin(60).await;
    drop(released);
    f.store.shutdown().await.unwrap();
    drop(f.store);
    let reopened = open_store(f.dir.path(), f.external, &[1, 2], 1, false).await;
    reopened.initialize_cluster().await.unwrap();
    let (client, mut session) = begin(&reopened, 0, 60).await;
    let binding = client.binding().unwrap().clone();
    let pages = received_pages(&session, &binding);
    upload(&mut session, &binding, &pages);
    let completed = session.finish(&binding, caller()).await.unwrap();
    assert_eq!(
        client
            .accept_report(&completed.report().encode().unwrap())
            .unwrap()
            .frozen_sequence(),
        3
    );
    drop(completed);
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn recipient_online_received_bytes_poison_and_exact_completeness() {
    let f = Fixture::new(2).await;
    for request in [103, 104, 105] {
        f.observe(request).await;
    }
    let before = f.ledger_bytes();
    for defect in [
        "row",
        "omit",
        "reorder",
        "repeat",
        "substitute",
        "cursor",
        "decode",
        "truncate",
    ] {
        let (client, mut session) = f.begin(60).await;
        let binding = client.binding().unwrap().clone();
        let pages = received_pages(&session, &binding);
        assert_eq!(pages.len(), 3);
        if defect == "truncate" {
            upload(&mut session, &binding, &pages[..2]);
            assert!(
                matches!(
                    session.finish(&binding, caller()).await,
                    Err(AuditAuthorityError::BindingMismatch)
                ),
                "RECEIVED_RANGE_COMPLETE"
            );
            continue;
        }
        let bad = match defect {
            "row" => {
                let mut value: serde_json::Value = serde_json::from_slice(&pages[0]).unwrap();
                let byte = value["rows"][0]["proof"]["signature"][0].as_u64().unwrap();
                value["rows"][0]["proof"]["signature"][0] = serde_json::json!(byte ^ 1);
                serde_json::to_vec(&value).unwrap()
            }
            "omit" | "reorder" => pages[1].clone(),
            "repeat" => {
                session
                    .accept_received_page(&binding, caller(), &pages[0])
                    .unwrap();
                pages[0].clone()
            }
            "substitute" => {
                let (other_client, other) = f.begin(60).await;
                received_pages(&other, other_client.binding().unwrap()).remove(0)
            }
            "cursor" => {
                let mut value: serde_json::Value = serde_json::from_slice(&pages[0]).unwrap();
                value["next"] = serde_json::Value::Null;
                serde_json::to_vec(&value).unwrap()
            }
            "decode" => pages[0][..8].to_vec(),
            _ => unreachable!(),
        };
        assert!(
            session
                .accept_received_page(&binding, caller(), &bad)
                .is_err(),
            "RECEIVED_PAGE_AUTHENTICATION: {defect}"
        );
        let intact = &pages[usize::from(defect == "repeat")];
        assert!(
            matches!(
                session.accept_received_page(&binding, caller(), intact),
                Err(AuditAuthorityError::BindingMismatch)
            ),
            "RECEIVED_FAILURE_POISONS: {defect}"
        );
        assert!(
            matches!(
                session.finish(&binding, caller()).await,
                Err(AuditAuthorityError::BindingMismatch)
            ),
            "POISONED_FINISH: {defect}"
        );
    }
    assert_eq!(f.ledger_bytes(), before);
    // Even a zero-row range requires the actual terminal page, covered separately
    // below. Here page generation alone must not count as page acceptance.
    let (client, session) = f.begin(60).await;
    let binding = client.binding().unwrap().clone();
    assert_eq!(received_pages(&session, &binding).len(), 3);
    assert!(
        matches!(
            session.finish(&binding, caller()).await,
            Err(AuditAuthorityError::BindingMismatch)
        ),
        "GENERATING_IS_NOT_RECEIVING"
    );
    f.store.shutdown().await.unwrap();
}

#[tokio::test]
async fn recipient_online_binds_caller_authority_nonce_manifest_and_report() {
    let f = Fixture::new(2).await;
    f.observe(106).await;
    let wrong_caller =
        AuditCaller::project(&privacy(), "another-tenant", "another-principal").unwrap();
    let wrong_authority = ConfigConsensusIdentity::new(
        opc_persist::ConfigConsensusClusterId::new("other-authority").unwrap(),
        opc_persist::ConfigConsensusConfigurationId::from_bytes([7; 32]),
        opc_persist::ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let wrong_request = AuditRecipientClient::new(wrong_authority, caller());
    assert!(
        matches!(
            f.store
                .begin_recipient_audit_export(
                    caller(),
                    0,
                    Duration::from_secs(60),
                    wrong_request.request()
                )
                .await,
            Err(AuditAuthorityError::BindingMismatch)
        ),
        "EXPECTED_AUTHORITY_BINDING"
    );
    let claim = AuditRecipientClient::new(topology().identity(), wrong_caller);
    assert!(
        matches!(
            f.store
                .begin_recipient_audit_export(caller(), 0, Duration::from_secs(60), claim.request())
                .await,
            Err(AuditAuthorityError::BindingMismatch)
        ),
        "AUTHENTICATED_CALLER_NOT_WIRE_CLAIM"
    );
    let (client, mut session) = f.begin(60).await;
    let binding = client.binding().unwrap().clone();
    assert!(
        matches!(
            session.page(&binding, wrong_caller, None, 1),
            Err(AuditAuthorityError::BindingMismatch)
        ),
        "PAGE_CALLER_BINDING"
    );
    let (other_client, other) = f.begin(60).await;
    assert!(
        matches!(
            session.page(other_client.binding().unwrap(), caller(), None, 1),
            Err(AuditAuthorityError::BindingMismatch)
        ),
        "PAGE_MANIFEST_BINDING"
    );
    let mut fresh = AuditRecipientClient::new(topology().identity(), caller());
    assert!(
        matches!(
            fresh.accept_opened(&binding.encode().unwrap()),
            Err(AuditAuthorityError::BindingMismatch)
        ),
        "FRESH_REQUEST_NONCE"
    );
    let pages = received_pages(&session, &binding);
    upload(&mut session, &binding, &pages);
    let completed = session.finish(&binding, caller()).await.unwrap();
    let bytes = completed.report().encode().unwrap();
    assert!(
        matches!(
            other_client.accept_report(&bytes),
            Err(AuditAuthorityError::BindingMismatch)
        ),
        "REPORT_EXACT_MANIFEST"
    );
    assert!(client.accept_report(&bytes).is_ok());
    drop((other, completed));
    // Exercise authenticated caller checks on both effect-free accepting and
    // finalization paths, not just the preceding page route.
    let (client, mut session) = f.begin(60).await;
    let binding = client.binding().unwrap().clone();
    let pages = received_pages(&session, &binding);
    assert!(
        matches!(
            session.accept_received_page(&binding, wrong_caller, &pages[0]),
            Err(AuditAuthorityError::BindingMismatch)
        ),
        "RECEIVE_CALLER_BINDING"
    );
    drop(session);
    let (client, mut session) = f.begin(60).await;
    let binding = client.binding().unwrap().clone();
    let pages = received_pages(&session, &binding);
    upload(&mut session, &binding, &pages);
    assert!(
        matches!(
            session.finish(&binding, wrong_caller).await,
            Err(AuditAuthorityError::BindingMismatch)
        ),
        "FINISH_CALLER_BINDING"
    );
    f.store.shutdown().await.unwrap();
}

#[tokio::test]
async fn recipient_online_checkpoint_outage_missing_and_rollback_refuse() {
    let f = Fixture::new(2).await;
    f.observe(107).await;
    let genesis = f.checkpoint();
    for missing in [false, true] {
        let (client, mut session) = f.begin(60).await;
        let binding = client.binding().unwrap().clone();
        let pages = received_pages(&session, &binding);
        upload(&mut session, &binding, &pages);
        let before = f.ledger_bytes();
        let writes = f.external.writes.load(Ordering::Acquire);
        if missing {
            *f.external.inner.value.lock().unwrap() = None;
        } else {
            f.external.inner.unavailable.store(true, Ordering::Release);
        }
        assert!(
            matches!(
                session.finish(&binding, caller()).await,
                Err(AuditAuthorityError::Unavailable)
            ),
            "FRESH_EXTERNAL_REQUIRED"
        );
        let fresh = AuditRecipientClient::new(topology().identity(), caller());
        assert!(
            matches!(
                f.store
                    .begin_recipient_audit_export(
                        caller(),
                        0,
                        Duration::from_secs(60),
                        fresh.request()
                    )
                    .await,
                Err(AuditAuthorityError::Unavailable)
            ),
            "FREEZE_EXTERNAL_REQUIRED"
        );
        assert_eq!(f.ledger_bytes(), before);
        assert_eq!(f.external.writes.load(Ordering::Acquire), writes);
        *f.external.inner.value.lock().unwrap() = Some(genesis.clone());
        f.external.inner.unavailable.store(false, Ordering::Release);
    }
    // Establish a genuine externally acknowledged mark, then move only the
    // synthetic independent provider back to its previous authentic value.
    let export = f
        .store
        .freeze_audit_export(caller(), 0, Duration::from_secs(60))
        .await
        .unwrap();
    let verified = verify_export(&export, topology().identity(), &[1, 2]);
    f.store
        .acknowledge_audit_export(&verified, caller())
        .await
        .unwrap();
    drop(export);
    let current = f.checkpoint();
    assert_eq!(current.sequence(), 1);
    let (client, mut session) = f.begin(60).await;
    let binding = client.binding().unwrap().clone();
    let pages = received_pages(&session, &binding);
    upload(&mut session, &binding, &pages);
    *f.external.inner.value.lock().unwrap() = Some(genesis);
    assert!(
        matches!(
            session.finish(&binding, caller()).await,
            Err(AuditAuthorityError::RollbackDetected)
        ),
        "FRESH_CHECKPOINT_ROLLBACK"
    );
    *f.external.inner.value.lock().unwrap() = Some(current);
    let (client, mut session) = f.begin(60).await;
    let binding = client.binding().unwrap().clone();
    let pages = received_pages(&session, &binding);
    upload(&mut session, &binding, &pages);
    drop(session.finish(&binding, caller()).await.unwrap());
    f.store.shutdown().await.unwrap();
}

#[tokio::test]
async fn recipient_online_authentic_conflicting_checkpoint_refuses() {
    let f = Fixture::new(1).await;
    let fork = Fixture::new(1).await;
    f.observe(111).await;
    fork.observe(112).await;
    for authority in [&f, &fork] {
        let export = authority
            .store
            .freeze_audit_export(caller(), 0, Duration::from_secs(60))
            .await
            .unwrap();
        let verified = verify_export(&export, topology().identity(), &[1, 2]);
        authority
            .store
            .acknowledge_audit_export(&verified, caller())
            .await
            .unwrap();
    }
    let original = f.checkpoint();
    let conflicting = fork.checkpoint();
    assert_eq!(original.sequence(), conflicting.sequence());
    assert_ne!(original, conflicting);
    let (client, mut session) = f.begin(60).await;
    let binding = client.binding().unwrap().clone();
    let pages = received_pages(&session, &binding);
    upload(&mut session, &binding, &pages);
    let before = f.ledger_bytes();
    // A real second history produced this authentic checkpoint under the same
    // synthetic identity/keys. No successful verification callback is involved.
    *f.external.inner.value.lock().unwrap() = Some(conflicting);
    assert!(
        matches!(
            session.finish(&binding, caller()).await,
            Err(AuditAuthorityError::BindingMismatch)
        ),
        "AUTHENTIC_EQUAL_SEQUENCE_FORK"
    );
    assert_eq!(f.ledger_bytes(), before);
    *f.external.inner.value.lock().unwrap() = Some(original);
    fork.store.shutdown().await.unwrap();
    f.store.shutdown().await.unwrap();
}

#[tokio::test]
async fn recipient_online_expiry_after_real_checkpoint_wait_refuses() {
    let f = Fixture::new(1).await;
    let (client, mut session) = f.begin(1).await;
    let binding = client.binding().unwrap().clone();
    let pages = received_pages(&session, &binding);
    upload(&mut session, &binding, &pages);
    let gate = Arc::new(LoadGate::default());
    *f.external.next_load.lock().unwrap() = Some(gate.clone());
    let mut pending = Box::pin(session.finish(&binding, caller()));
    tokio::select! {
        entered = tokio::time::timeout(Duration::from_secs(10), gate.entered.notified()) => {
            entered.unwrap();
            assert_eq!(gate.active.load(Ordering::Acquire), 1);
        }
        _ = &mut pending => panic!("finish escaped the real independent provider gate"),
    }
    tokio::time::sleep(Duration::from_millis(1100)).await;
    gate.release.notify_one();
    assert!(
        matches!(pending.await, Err(AuditAuthorityError::Expired)),
        "POST_WAIT_FIXED_EXPIRY"
    );
    assert_eq!(gate.active.load(Ordering::Acquire), 0);
    let (_, session) = f.begin(60).await;
    drop(session);
    f.store.shutdown().await.unwrap();
}

#[tokio::test]
async fn recipient_online_cancelled_provider_wait_releases_exact_owner() {
    let f = Fixture::new(1).await;
    for at_finish in [false, true] {
        let gate = Arc::new(LoadGate::default());
        let request_client = AuditRecipientClient::new(topology().identity(), caller());
        if at_finish {
            let (client, mut session) = f.begin(60).await;
            let binding = client.binding().unwrap().clone();
            let pages = received_pages(&session, &binding);
            upload(&mut session, &binding, &pages);
            *f.external.next_load.lock().unwrap() = Some(gate.clone());
            let mut pending = Box::pin(session.finish(&binding, caller()));
            tokio::select! {
                entered = tokio::time::timeout(Duration::from_secs(10), gate.entered.notified()) => {
                    entered.unwrap();
                    assert_eq!(gate.active.load(Ordering::Acquire), 1);
                }
                _ = &mut pending => panic!("finish escaped the real independent provider gate"),
            }
            assert!(
                matches!(
                    f.store
                        .begin_recipient_audit_export(
                            caller(),
                            0,
                            Duration::from_secs(60),
                            request_client.request()
                        )
                        .await,
                    Err(AuditAuthorityError::Full)
                ),
                "PENDING_FINISH_OWNS_PERMIT"
            );
            drop(pending);
        } else {
            *f.external.next_load.lock().unwrap() = Some(gate.clone());
            let mut pending = Box::pin(f.store.begin_recipient_audit_export(
                caller(),
                0,
                Duration::from_secs(60),
                request_client.request(),
            ));
            tokio::select! {
                entered = tokio::time::timeout(Duration::from_secs(10), gate.entered.notified()) => {
                    entered.unwrap();
                    assert_eq!(gate.active.load(Ordering::Acquire), 1);
                }
                _ = &mut pending => panic!("freeze escaped the real independent provider gate"),
            }
            assert!(
                matches!(
                    f.store
                        .begin_recipient_audit_export(
                            caller(),
                            0,
                            Duration::from_secs(60),
                            request_client.request()
                        )
                        .await,
                    Err(AuditAuthorityError::Full)
                ),
                "PENDING_FREEZE_OWNS_PERMIT"
            );
            drop(pending);
        }
        assert_eq!(
            gate.active.load(Ordering::Acquire),
            0,
            "CANCELLED_PROVIDER_FUTURE_DROPPED"
        );
        gate.release.notify_waiters();
        let (client, mut session) = f.begin(60).await;
        let binding = client.binding().unwrap().clone();
        let pages = received_pages(&session, &binding);
        upload(&mut session, &binding, &pages);
        drop(session.finish(&binding, caller()).await.unwrap());
    }
    assert_eq!(f.checkpoint().sequence(), 0);
    f.store.shutdown().await.unwrap();
}

#[tokio::test]
async fn recipient_online_fixed_expiry_bounds_and_empty_received_page() {
    let f = Fixture::new(1).await;
    let request = AuditRecipientClient::new(topology().identity(), caller());
    for duration in [
        Duration::ZERO,
        Duration::from_secs(3601),
        Duration::from_nanos(1),
    ] {
        assert!(matches!(
            f.store
                .begin_recipient_audit_export(caller(), 0, duration, request.request())
                .await,
            Err(AuditAuthorityError::InvalidInput)
        ));
    }
    let (client, session) = f.begin(60).await;
    let binding = client.binding().unwrap().clone();
    assert!(session.page(&binding, caller(), None, 257).is_err());
    assert!(session.page(&binding, caller(), None, 0).is_err());
    assert!(
        matches!(
            session.finish(&binding, caller()).await,
            Err(AuditAuthorityError::BindingMismatch)
        ),
        "EMPTY_RANGE_REQUIRES_RECEIVED_PAGE"
    );
    let (client, mut session) = f.begin(1).await;
    let binding = client.binding().unwrap().clone();
    let pages = received_pages(&session, &binding);
    assert_eq!(pages.len(), 1);
    upload(&mut session, &binding, &pages);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(matches!(
        session.page(&binding, caller(), None, 1),
        Err(AuditAuthorityError::Expired)
    ));
    assert!(
        matches!(
            session.finish(&binding, caller()).await,
            Err(AuditAuthorityError::Expired)
        ),
        "FIXED_SESSION_EXPIRY"
    );
    let (client, mut session) = f.begin(60).await;
    let binding = client.binding().unwrap().clone();
    let pages = received_pages(&session, &binding);
    upload(&mut session, &binding, &pages);
    assert!(
        matches!(
            session.accept_received_page(&binding, caller(), &pages[0]),
            Err(AuditAuthorityError::BindingMismatch)
        ),
        "EMPTY_TERMINAL_ONCE"
    );
    drop(session);
    let (client, mut session) = f.begin(60).await;
    let binding = client.binding().unwrap().clone();
    assert!(
        matches!(
            session.accept_received_page(&binding, caller(), &vec![b' '; 16 * 1024 * 1024 + 1]),
            Err(AuditAuthorityError::InvalidInput)
        ),
        "RECEIVED_DECODER_BOUND"
    );
    drop(session);
    f.store.shutdown().await.unwrap();
}

#[tokio::test]
async fn recipient_online_frozen_pages_survive_pruning_without_coverage_upgrade() {
    let f = Fixture::new(2).await;
    f.observe(108).await;
    let transition = f.store.prepare_audit_key_transition(2).await.unwrap();
    f.store
        .activate_audit_key_transition(&transition)
        .await
        .unwrap();
    f.observe(109).await;
    let (client, mut session) = f.begin(60).await;
    let binding = client.binding().unwrap().clone();
    let pages = received_pages(&session, &binding);
    for through in [3, 4] {
        if through == 4 {
            f.observe(110).await;
        }
        let floor = if through == 3 { 0 } else { 3 };
        let export = f
            .store
            .freeze_audit_export(caller(), floor, Duration::from_secs(60))
            .await
            .unwrap();
        let verified = verify_export(&export, topology().identity(), &[1, 2]);
        f.store
            .acknowledge_audit_export(&verified, caller())
            .await
            .unwrap();
        drop(export);
        tokio::time::sleep(Duration::from_millis(3100)).await;
        f.store.retain_audit_history_through(through).await.unwrap();
    }
    assert_eq!(f.checkpoint().sequence(), 4);
    assert_eq!(
        received_pages(&session, &binding),
        pages,
        "FROZEN_PAGES_SURVIVE_LIVE_PRUNE"
    );
    upload(&mut session, &binding, &pages);
    let completed = session.finish(&binding, caller()).await.unwrap();
    let report = client
        .accept_report(&completed.report().encode().unwrap())
        .unwrap();
    assert_eq!(report.frozen_sequence(), 3);
    assert_eq!(
        report.checkpoint_at_freeze().sequence(),
        0,
        "LATER_CHECKPOINT_IS_NOT_FROZEN_COVERAGE"
    );
    assert_eq!(report.checkpoint_at_finish().sequence(), 4);
    let fresh = AuditRecipientClient::new(topology().identity(), caller());
    assert!(
        matches!(
            f.store
                .begin_recipient_audit_export(caller(), 0, Duration::from_secs(60), fresh.request())
                .await,
            Err(AuditAuthorityError::Pruned)
        ),
        "EXACT_EXPECTED_FLOOR"
    );
    assert!(matches!(
        f.store
            .begin_recipient_audit_export(caller(), 5, Duration::from_secs(60), fresh.request())
            .await,
        Err(AuditAuthorityError::InvalidInput)
    ));
    drop(completed);
    f.store.shutdown().await.unwrap();
    drop(f.store);
    // The authentic retained floor and external checkpoint now require only 2.
    let reopened = open_store(f.dir.path(), f.external, &[2], 1, false).await;
    reopened.initialize_cluster().await.unwrap();
    let (client, mut session) = begin(&reopened, 4, 60).await;
    let binding = client.binding().unwrap().clone();
    let pages = received_pages(&session, &binding);
    upload(&mut session, &binding, &pages);
    let completed = session.finish(&binding, caller()).await.unwrap();
    assert_eq!(
        client
            .accept_report(&completed.report().encode().unwrap())
            .unwrap()
            .frozen_floor(),
        4
    );
    drop(completed);
    reopened.shutdown().await.unwrap();
}
