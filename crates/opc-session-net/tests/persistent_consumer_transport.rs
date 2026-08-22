//! Live contract tests for the bounded persistent consumer transport.
//!
//! These exercise only the typed consumer port.  They deliberately do not
//! reach through to consensus, replication, or backend implementation APIs.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::{self, BoxStream, StreamExt};
use opc_consensus::{derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch};
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_session_net::{
    conservative_payload_budget, ConnectionLifecyclePolicy, PersistentSessionConsumerClient,
    PersistentSessionConsumerConfig, PersistentSessionConsumerDiagnostics,
    PersistentSessionConsumerExecuteError, RemoteAddrResolver, SessionConsumerAuthorizer,
    SessionConsumerClientError, SessionQuorumConsumerServer, SessionReauthenticationControl,
    StatelessSessionConsumerClient, MAX_NEGOTIATED_FRAME_SIZE,
};
use opc_session_store::{
    BackendCapabilities, ConsensusSessionStore, QuorumReplicaDescriptor, ReplicaBackingIdentity,
    ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, SessionConsensusIdentity,
    SessionConsumerChange, SessionConsumerIdentity, SessionConsumerOperation,
    SessionConsumerRejection, SessionConsumerRequest, SessionConsumerRequestId,
    SessionConsumerResponse, SessionConsumerScope, SessionConsumerStoreError, SessionKey,
    SessionKeyType, SessionQuorumConsumer, SqliteSessionBackend, ValidatedQuorumTopology,
};
use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};
use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore};

fn transported_capabilities() -> BackendCapabilities {
    BackendCapabilities {
        max_value_bytes: conservative_payload_budget(MAX_NEGOTIATED_FRAME_SIZE),
        ..BackendCapabilities::all_enabled()
    }
}

struct TestPki {
    ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl TestPki {
    fn new() -> Self {
        let key = rcgen::KeyPair::generate().expect("test CA key");
        let mut parameters = rcgen::CertificateParams::default();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "persistent consumer test CA");
        Self {
            ca: rcgen::CertifiedIssuer::self_signed(parameters, key).expect("test CA certificate"),
        }
    }

    fn client_config(&self, spiffe_id: &str) -> AuthenticatedClientConfig {
        let (_source, receiver) = tokio::sync::watch::channel(Some(self.identity_state(spiffe_id)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("test client TLS config")
    }

    fn server_config(&self, spiffe_id: &str) -> AuthenticatedServerConfig {
        let (_source, receiver) = tokio::sync::watch::channel(Some(self.identity_state(spiffe_id)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("test server TLS config")
    }

    fn identity_state(&self, spiffe_id: &str) -> opc_identity::IdentityState {
        let mut parameters = rcgen::CertificateParams::default();
        parameters.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(spiffe_id).expect("test SPIFFE URI"),
        ));
        let now = time::OffsetDateTime::now_utc();
        parameters.not_before = now - time::Duration::days(1);
        parameters.not_after = now + time::Duration::days(1);
        let key = rcgen::KeyPair::generate().expect("test leaf key");
        let certificate = parameters
            .signed_by(&key, &self.ca)
            .expect("test leaf certificate");
        let certificates =
            parse_certs_pem(&(certificate.pem() + &self.ca.pem())).expect("test certificate chain");
        let private_key = parse_key_pem(&key.serialize_pem()).expect("test private key");
        let mut bundles = opc_identity::TrustBundleSet::new();
        bundles.insert(TrustBundle {
            trust_domain: opc_identity::TrustDomain::new("test.example").expect("trust domain"),
            certificates: parse_certs_pem(&self.ca.pem()).expect("test trust bundle"),
        });
        build_identity_state(certificates, private_key, bundles).expect("test identity state")
    }
}

#[derive(Default)]
struct ControlledConsumer {
    calls: AtomicUsize,
    active_executes: AtomicUsize,
    active_executes_changed: Notify,
    active_watch_setups: AtomicUsize,
    active_watch_setups_changed: Notify,
    block_watch_setup: AtomicBool,
    watch_setup_released: Notify,
    block: AtomicBool,
    blocked_remaining: AtomicUsize,
    entered: Notify,
    released: Notify,
    request_order: Mutex<Vec<opc_session_store::SessionConsumerRequestId>>,
    watch_entry: Mutex<Option<SessionConsumerChange>>,
    watch_entry_limit: AtomicUsize,
    watch_emitted: Arc<AtomicUsize>,
    watch_emitted_notify: Arc<Notify>,
    watch_blocked: Arc<AtomicBool>,
    watch_released: Arc<Notify>,
    watch_stays_open: AtomicBool,
    watch_closes_without_item: AtomicBool,
    watch_error: Mutex<Option<SessionConsumerStoreError>>,
    watch_starts: Mutex<Vec<u64>>,
    watch_started_at: Mutex<Vec<Instant>>,
}

struct ActiveServiceCall<'a> {
    active: &'a AtomicUsize,
    changed: &'a Notify,
}

impl Drop for ActiveServiceCall<'_> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
        self.changed.notify_waiters();
    }
}

impl ControlledConsumer {
    fn arm_blocks(&self, count: usize) {
        self.blocked_remaining.store(count, Ordering::SeqCst);
        self.block.store(count != 0, Ordering::SeqCst);
    }

    async fn wait_until_entered(&self, expected: usize) {
        while self.calls.load(Ordering::SeqCst) < expected {
            tokio::task::yield_now().await;
        }
    }

    async fn wait_until_no_active_execute(&self) {
        loop {
            let changed = self.active_executes_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.active_executes.load(Ordering::SeqCst) == 0 {
                return;
            }
            changed.await;
        }
    }

    fn arm_watch_setup_block(&self) {
        self.block_watch_setup.store(true, Ordering::SeqCst);
    }

    async fn wait_until_watch_setup_entered(&self) {
        loop {
            let changed = self.active_watch_setups_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.active_watch_setups.load(Ordering::SeqCst) != 0 {
                return;
            }
            changed.await;
        }
    }

    async fn wait_until_no_active_watch_setup(&self) {
        loop {
            let changed = self.active_watch_setups_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.active_watch_setups.load(Ordering::SeqCst) == 0 {
                return;
            }
            changed.await;
        }
    }

    fn release_watch_setup(&self) {
        self.block_watch_setup.store(false, Ordering::SeqCst);
        self.watch_setup_released.notify_waiters();
    }

    fn release(&self) {
        self.block.store(false, Ordering::SeqCst);
        self.released.notify_waiters();
    }

    fn request_order(&self) -> Vec<opc_session_store::SessionConsumerRequestId> {
        self.request_order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn emit_watch_entries_then_close(&self, entry: SessionConsumerChange, count: usize) {
        assert!(
            count > 0,
            "finite watch fixture must emit at least one entry"
        );
        self.watch_entry_limit.store(count, Ordering::SeqCst);
        self.watch_stays_open.store(false, Ordering::SeqCst);
        *self
            .watch_entry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(entry);
    }

    fn arm_watch_block(&self) {
        self.watch_blocked.store(true, Ordering::SeqCst);
    }

    fn release_watch(&self) {
        self.watch_blocked.store(false, Ordering::SeqCst);
        self.watch_released.notify_waiters();
    }

    fn emit_one_watch_entry_then_pending(&self, entry: SessionConsumerChange) {
        self.watch_entry_limit.store(1, Ordering::SeqCst);
        self.watch_stays_open.store(true, Ordering::SeqCst);
        *self
            .watch_entry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(entry);
    }

    fn close_watch_without_item(&self) {
        self.watch_closes_without_item.store(true, Ordering::SeqCst);
    }

    fn emit_watch_entries_then_pending(&self, entry: SessionConsumerChange, count: usize) {
        assert!(
            count > 0,
            "pending watch fixture must emit at least one entry"
        );
        self.watch_entry_limit.store(count, Ordering::SeqCst);
        self.watch_stays_open.store(true, Ordering::SeqCst);
        *self
            .watch_entry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(entry);
    }

    fn emit_terminal_watch_error(&self, error: SessionConsumerStoreError) {
        *self
            .watch_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
    }

    fn watch_starts(&self) -> Vec<u64> {
        self.watch_starts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn watch_started_at(&self) -> Vec<Instant> {
        self.watch_started_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    async fn wait_for_watch_emissions(&self, expected: usize) {
        loop {
            let notified = self.watch_emitted_notify.notified();
            if self.watch_emitted.load(Ordering::SeqCst) >= expected {
                return;
            }
            notified.await;
        }
    }
}

#[async_trait]
impl SessionQuorumConsumer for ControlledConsumer {
    async fn execute(
        &self,
        _identity: &SessionConsumerIdentity,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        self.active_executes.fetch_add(1, Ordering::SeqCst);
        let _active = ActiveServiceCall {
            active: &self.active_executes,
            changed: &self.active_executes_changed,
        };
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.request_order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.request_id());
        self.entered.notify_waiters();
        if self
            .blocked_remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            while self.block.load(Ordering::SeqCst) {
                self.released.notified().await;
            }
        }
        if matches!(request.operation(), SessionConsumerOperation::Watch { .. }) {
            SessionConsumerResponse::WatchOpened
        } else {
            SessionConsumerResponse::Capabilities(BackendCapabilities::all_enabled())
        }
    }

    async fn watch(
        &self,
        _identity: &SessionConsumerIdentity,
        _scope: SessionConsumerScope,
        start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        self.active_watch_setups.fetch_add(1, Ordering::SeqCst);
        self.active_watch_setups_changed.notify_waiters();
        let _active = ActiveServiceCall {
            active: &self.active_watch_setups,
            changed: &self.active_watch_setups_changed,
        };
        while self.block_watch_setup.load(Ordering::SeqCst) {
            self.watch_setup_released.notified().await;
        }
        self.watch_starts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(start_sequence);
        self.watch_started_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Instant::now());
        if let Some(error) = *self
            .watch_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            return Ok(stream::once(async move { Err(error) }).boxed());
        }
        if self.watch_closes_without_item.load(Ordering::SeqCst) {
            return Ok(stream::empty().boxed());
        }
        let entry = self
            .watch_entry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(entry) = entry else {
            return Ok(stream::pending().boxed());
        };
        // Match the public store cursor contract: zero is the empty-head
        // sentinel and therefore starts at inclusive sequence one. Do not
        // rewrite a synthetic entry to sequence zero, which production
        // backends can never emit.
        let start_sequence = start_sequence.max(1);
        if self.watch_blocked.load(Ordering::SeqCst) {
            let watch_blocked = Arc::clone(&self.watch_blocked);
            let watch_released = Arc::clone(&self.watch_released);
            return Ok(stream::once(async move {
                while watch_blocked.load(Ordering::SeqCst) {
                    watch_released.notified().await;
                }
                Ok::<_, SessionConsumerStoreError>(watch_change_at_sequence(&entry, start_sequence))
            })
            .boxed());
        }
        if start_sequence == u64::MAX {
            self.watch_emitted.fetch_add(1, Ordering::SeqCst);
            self.watch_emitted_notify.notify_waiters();
            return Ok(stream::once(async move {
                Ok::<_, SessionConsumerStoreError>(watch_change_at_sequence(&entry, u64::MAX))
            })
            .boxed());
        }
        let entry_limit = self.watch_entry_limit.load(Ordering::SeqCst);
        let emitted = Arc::clone(&self.watch_emitted);
        if entry_limit == 0 {
            let emitted_notify = Arc::clone(&self.watch_emitted_notify);
            Ok(stream::iter(start_sequence..)
                .map(move |sequence| {
                    emitted.fetch_add(1, Ordering::SeqCst);
                    emitted_notify.notify_waiters();
                    Ok::<_, SessionConsumerStoreError>(watch_change_at_sequence(&entry, sequence))
                })
                .boxed())
        } else if self.watch_stays_open.load(Ordering::SeqCst) {
            let emitted_notify = Arc::clone(&self.watch_emitted_notify);
            Ok(stream::iter(start_sequence..)
                .map(move |sequence| {
                    emitted.fetch_add(1, Ordering::SeqCst);
                    emitted_notify.notify_waiters();
                    Ok::<_, SessionConsumerStoreError>(watch_change_at_sequence(&entry, sequence))
                })
                .take(entry_limit)
                .chain(stream::pending())
                .boxed())
        } else {
            let emitted_notify = Arc::clone(&self.watch_emitted_notify);
            Ok(stream::iter(start_sequence..)
                .map(move |sequence| {
                    emitted.fetch_add(1, Ordering::SeqCst);
                    emitted_notify.notify_waiters();
                    Ok::<_, SessionConsumerStoreError>(watch_change_at_sequence(&entry, sequence))
                })
                .take(entry_limit)
                .boxed())
        }
    }
}

fn large_watch_change() -> SessionConsumerChange {
    let key = SessionKey {
        tenant: TenantId::new("watch-pressure").expect("test tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(vec![7_u8; 64])
            .try_into()
            .expect("maximum bounded stable ID"),
    };
    let item = serde_json::json!({
        "key": serde_json::to_value(key).expect("watch key encodes"),
        "kind": "RecordWritten",
    });
    let change: SessionConsumerChange = serde_json::from_value(serde_json::json!({
        "sequence": 1,
        "changes": vec![item; 1_700],
    }))
    .expect("synthetic bounded watch change decodes");
    let encoded = serde_json::to_vec(&change).expect("watch change encodes");
    assert!(
        (256 * 1024..512 * 1024).contains(&encoded.len()),
        "fixture must consume over half of the fixed byte queue without exceeding it: {}",
        encoded.len()
    );
    change
}

fn watch_result_envelope_edge_change() -> SessionConsumerChange {
    let key = SessionKey {
        tenant: TenantId::new("watch-envelope-edge").expect("test tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(vec![9_u8; 64])
            .try_into()
            .expect("maximum bounded stable ID"),
    };
    let item = serde_json::json!({
        "key": serde_json::to_value(key).expect("watch key encodes"),
        "kind": "RecordWritten",
    });
    let edge_key = SessionKey {
        tenant: TenantId::new("watch-envelope-edge").expect("test tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(vec![255_u8; 64])
            .try_into()
            .expect("maximum bounded stable ID"),
    };
    let edge_item = serde_json::json!({
        "key": serde_json::to_value(edge_key).expect("edge watch key encodes"),
        "kind": "RecordWritten",
    });
    let mut changes = vec![item; 2_121];
    changes.push(edge_item);
    let change: SessionConsumerChange = serde_json::from_value(serde_json::json!({
        "sequence": 1,
        "changes": changes,
    }))
    .expect("synthetic envelope-edge change decodes");
    let bare = serde_json::to_vec(&change).expect("bare watch entry encodes");
    let queued = serde_json::to_vec(&Ok::<_, SessionConsumerStoreError>(change.clone()))
        .expect("queued watch result encodes");
    assert_eq!(queued.len(), bare.len() + 7, "Result::Ok adds seven bytes");
    assert!(
        bare.len() <= 512 * 1024 && queued.len() > 512 * 1024,
        "fixture must straddle the exact local byte cap: bare={}, queued={}",
        bare.len(),
        queued.len(),
    );
    change
}

fn exact_watch_byte_budget_change() -> SessionConsumerChange {
    const BYTE_CAP: usize = 512 * 1024;
    let ordinary_key = SessionKey {
        tenant: TenantId::new("watch-exact-cap").expect("test tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(vec![0_u8; 64])
            .try_into()
            .expect("maximum bounded stable ID"),
    };
    let ordinary = serde_json::json!({
        "key": serde_json::to_value(ordinary_key).expect("ordinary watch key encodes"),
        "kind": "RecordWritten",
    });

    // Two 64-byte stable IDs provide 256 single-byte JSON-width increments:
    // `0` -> `10` adds one byte and `0` -> `100` adds two. That covers the
    // complete spacing between adjacent repeated projections without trial
    // allocations proportional to the byte cap.
    for ordinary_count in 2_000..=2_300 {
        let build = |first: Vec<u8>, second: Vec<u8>| {
            let edge = |stable_id: Vec<u8>| {
                let key = SessionKey {
                    tenant: TenantId::new("watch-exact-cap").expect("test tenant"),
                    nf_kind: NetworkFunctionKind::smf(),
                    key_type: SessionKeyType::PduSession,
                    stable_id: Bytes::from(stable_id)
                        .try_into()
                        .expect("maximum bounded stable ID"),
                };
                serde_json::json!({
                    "key": serde_json::to_value(key).expect("edge watch key encodes"),
                    "kind": "RecordWritten",
                })
            };
            let mut changes = vec![ordinary.clone(); ordinary_count];
            changes.push(edge(first));
            changes.push(edge(second));
            serde_json::from_value::<SessionConsumerChange>(serde_json::json!({
                "sequence": 1,
                "changes": changes,
            }))
            .expect("synthetic exact-cap watch change decodes")
        };
        let baseline = build(vec![0_u8; 64], vec![0_u8; 64]);
        let baseline_len = serde_json::to_vec(&Ok::<_, SessionConsumerStoreError>(baseline))
            .expect("baseline queued watch result encodes")
            .len();
        let Some(delta) = BYTE_CAP.checked_sub(baseline_len) else {
            continue;
        };
        if delta > 256 {
            continue;
        }
        let mut bytes = [0_u8; 128];
        let three_digit = delta / 2;
        for byte in bytes.iter_mut().take(three_digit) {
            *byte = 100;
        }
        if delta % 2 == 1 {
            bytes[three_digit] = 10;
        }
        let exact = build(bytes[..64].to_vec(), bytes[64..].to_vec());
        assert_eq!(
            serde_json::to_vec(&Ok::<_, SessionConsumerStoreError>(exact.clone()))
                .expect("exact queued watch result encodes")
                .len(),
            BYTE_CAP,
            "fixture consumes every local byte permit exactly"
        );
        return exact;
    }
    panic!("unable to construct the exact fixed watch-byte boundary");
}

fn small_watch_change_at(sequence: u64) -> SessionConsumerChange {
    let key = SessionKey {
        tenant: TenantId::new("watch-queue").expect("test tenant"),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(b"opaque-watch-queue")
            .try_into()
            .expect("bounded stable ID"),
    };
    serde_json::from_value(serde_json::json!({
        "sequence": sequence,
        "changes": [{
            "key": serde_json::to_value(key).expect("watch key encodes"),
            "kind": "RecordWritten",
        }],
    }))
    .expect("small synthetic watch change decodes")
}

fn small_watch_change() -> SessionConsumerChange {
    small_watch_change_at(1)
}

fn watch_change_at_sequence(entry: &SessionConsumerChange, sequence: u64) -> SessionConsumerChange {
    let mut encoded = serde_json::to_value(entry).expect("watch fixture encodes");
    encoded["sequence"] = serde_json::Value::from(sequence);
    serde_json::from_value(encoded).expect("watch fixture sequence replaces")
}

fn assert_fixed_zero_diagnostics(diagnostics: PersistentSessionConsumerDiagnostics) {
    // Keep this exhaustive literal: adding an identifier-bearing field to the
    // public snapshot must be a deliberate compatibility decision, rather
    // than silently inheriting `Default` in this boundary test.
    assert_eq!(
        diagnostics,
        PersistentSessionConsumerDiagnostics {
            setup_attempts: 0,
            setup_failures: 0,
            setup_successes: 0,
            resolve_attempts: 0,
            resolve_failures: 0,
            tcp_attempts: 0,
            tcp_failures: 0,
            tls_attempts: 0,
            tls_failures: 0,
            hello_attempts: 0,
            hello_failures: 0,
            pool_wait_current: 0,
            pool_wait_max: 0,
            pool_wait_count: 0,
            pool_wait_max_duration_millis: 0,
            pool_wait_oldest_age_millis: 0,
            active: 0,
            max_active: 0,
            idle: 0,
            reused: 0,
            reconnects: 0,
            failures: 0,
            queued: 0,
            inflight: 0,
            max_inflight: 0,
            watch_active: 0,
            max_watch_active: 0,
            watch_buffered: 0,
            successes: 0,
            not_transmitted: 0,
            outcome_unknown: 0,
            overload: 0,
            shutdown: 0,
            authentication: 0,
            scope: 0,
            protocol: 0,
            deadline: 0,
        }
    );
}

fn spiffe(name: &str) -> String {
    format!("spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/{name}")
}

async fn authorizer_and_scope(
    client_spiffe: &str,
) -> (SessionConsumerAuthorizer, SessionConsumerScope) {
    let snapshots = tempfile::tempdir().expect("snapshot directory");
    let replica_id = ReplicaId::new("persistent-consumer-test").expect("replica ID");
    let descriptor = QuorumReplicaDescriptor::new(
        replica_id.clone(),
        ReplicaEndpoint::new("persistent-consumer.test.invalid", 7443).expect("endpoint"),
        ReplicaTlsIdentity::new(spiffe("member")).expect("member TLS identity"),
        ReplicaFailureDomain::new("persistent-consumer-zone").expect("failure domain"),
        ReplicaBackingIdentity::new("persistent-consumer-disk").expect("backing identity"),
    );
    let cluster = ConsensusClusterId::new("persistent-consumer-test").expect("cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(1).expect("configuration epoch");
    let configuration =
        derive_configuration_id(cluster, epoch, &[descriptor.configuration_fingerprint()]);
    let topology = ValidatedQuorumTopology::try_new_consensus_lab_singleton(
        replica_id,
        vec![descriptor],
        SessionConsensusIdentity::new(cluster, configuration, epoch),
    )
    .expect("singleton topology");
    let store = ConsensusSessionStore::open(
        topology,
        SqliteSessionBackend::in_memory().expect("SQLite backend"),
        snapshots.path(),
        Default::default(),
    )
    .await
    .expect("open store");
    store.initialize_cluster().await.expect("initialize store");
    let manifest = store
        .consumer_authorization_manifest()
        .await
        .expect("consumer authorization manifest");
    let scope = manifest.scope();
    let authorizer = SessionConsumerAuthorizer::try_new(
        manifest,
        [SpiffeId::new(client_spiffe).expect("client SPIFFE")],
    )
    .expect("consumer authorizer");
    (authorizer, scope)
}

fn config(
    request_connections: usize,
    pending_calls: usize,
    watch_connections: usize,
) -> PersistentSessionConsumerConfig {
    PersistentSessionConsumerConfig::try_new(
        request_connections,
        pending_calls,
        Duration::from_millis(250),
        watch_connections,
        Duration::from_millis(1_500),
        2,
        Duration::ZERO,
        Duration::from_secs(1),
    )
    .expect("bounded persistent config")
}

fn persistent_client(
    pki: &TestPki,
    resolver: RemoteAddrResolver,
    server_name: rustls_pki_types::ServerName<'static>,
    server_spiffe: &str,
    client_spiffe: &str,
    scope: SessionConsumerScope,
    config: PersistentSessionConsumerConfig,
) -> PersistentSessionConsumerClient {
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        server_name,
        SpiffeId::new(server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(2));
    PersistentSessionConsumerClient::try_from_stateless(stateless, config)
        .expect("persistent client")
}

struct ResolverAttemptGuard {
    active: Arc<AtomicUsize>,
    first_dropped: Arc<AtomicBool>,
    ordinal: usize,
}

impl ResolverAttemptGuard {
    fn enter(
        active: Arc<AtomicUsize>,
        peak: &AtomicUsize,
        first_dropped: Arc<AtomicBool>,
        ordinal: usize,
    ) -> Self {
        let concurrent = active.fetch_add(1, Ordering::SeqCst) + 1;
        let mut observed_peak = peak.load(Ordering::SeqCst);
        while concurrent > observed_peak {
            match peak.compare_exchange_weak(
                observed_peak,
                concurrent,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => observed_peak = actual,
            }
        }
        Self {
            active,
            first_dropped,
            ordinal,
        }
    }
}

impl Drop for ResolverAttemptGuard {
    fn drop(&mut self) {
        if self.ordinal == 1 {
            self.first_dropped.store(true, Ordering::SeqCst);
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn persistent_pool_shares_one_recovery_probe_across_twelve_callers() {
    const CALLERS: usize = 12;
    let pki = TestPki::new();
    let server_spiffe = spiffe("shared-recovery-gate-server");
    let client_spiffe = spiffe("shared-recovery-gate-client");
    let (_authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let lifecycle = ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(2),
        Duration::from_millis(100),
        Duration::from_millis(50),
        Duration::from_millis(400),
        Duration::ZERO,
    )
    .expect("deterministic reconnect lifecycle");
    let resolver_attempts = Arc::new(AtomicUsize::new(0));
    let concurrent_resolvers = Arc::new(AtomicUsize::new(0));
    let peak_resolvers = Arc::new(AtomicUsize::new(0));
    let resolver_timestamps = Arc::new(Mutex::new(Vec::new()));
    let resolver_entered = Arc::new(Notify::new());
    let release_resolvers = Arc::new(AtomicBool::new(false));
    let resolver_released = Arc::new(Notify::new());
    let resolver: RemoteAddrResolver = {
        let resolver_attempts = Arc::clone(&resolver_attempts);
        let concurrent_resolvers = Arc::clone(&concurrent_resolvers);
        let peak_resolvers = Arc::clone(&peak_resolvers);
        let resolver_timestamps = Arc::clone(&resolver_timestamps);
        let resolver_entered = Arc::clone(&resolver_entered);
        let release_resolvers = Arc::clone(&release_resolvers);
        let resolver_released = Arc::clone(&resolver_released);
        Arc::new(move || {
            let resolver_attempts = Arc::clone(&resolver_attempts);
            let concurrent_resolvers = Arc::clone(&concurrent_resolvers);
            let peak_resolvers = Arc::clone(&peak_resolvers);
            let resolver_timestamps = Arc::clone(&resolver_timestamps);
            let resolver_entered = Arc::clone(&resolver_entered);
            let release_resolvers = Arc::clone(&release_resolvers);
            let resolver_released = Arc::clone(&resolver_released);
            Box::pin(async move {
                resolver_attempts.fetch_add(1, Ordering::SeqCst);
                resolver_timestamps
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(tokio::time::Instant::now());
                let concurrent = concurrent_resolvers.fetch_add(1, Ordering::SeqCst) + 1;
                let mut observed_peak = peak_resolvers.load(Ordering::SeqCst);
                while concurrent > observed_peak {
                    match peak_resolvers.compare_exchange_weak(
                        observed_peak,
                        concurrent,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => break,
                        Err(actual) => observed_peak = actual,
                    }
                }
                resolver_entered.notify_waiters();
                loop {
                    let released = resolver_released.notified();
                    tokio::pin!(released);
                    released.as_mut().enable();
                    if release_resolvers.load(Ordering::SeqCst) {
                        break;
                    }
                    released.await;
                }
                concurrent_resolvers.fetch_sub(1, Ordering::SeqCst);
                Err(std::io::Error::other("test resolver unavailable"))
            })
        })
    };
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::try_from("persistent-consumer.test.invalid")
            .expect("test server name"),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(2))
    .with_connection_lifecycle(lifecycle);
    let client = PersistentSessionConsumerClient::try_from_stateless(
        stateless,
        PersistentSessionConsumerConfig::try_new(
            CALLERS,
            0,
            Duration::from_millis(250),
            1,
            Duration::from_millis(1_500),
            1,
            Duration::ZERO,
            Duration::from_secs(1),
        )
        .expect("fixed concurrent recovery config"),
    )
    .expect("persistent client");
    let start = Arc::new(tokio::sync::Barrier::new(CALLERS + 1));
    let mut callers = Vec::with_capacity(CALLERS);
    for _ in 0..CALLERS {
        let client = client.clone();
        let start = Arc::clone(&start);
        callers.push(tokio::spawn(async move {
            start.wait().await;
            client.capabilities().await
        }));
    }
    start.wait().await;

    tokio::time::timeout(Duration::from_millis(25), async {
        loop {
            let entered = resolver_entered.notified();
            if resolver_attempts.load(Ordering::SeqCst) == 1 {
                return;
            }
            entered.await;
        }
    })
    .await
    .expect("one shared recovery probe starts promptly");
    for _ in 0..CALLERS {
        tokio::task::yield_now().await;
    }
    let observed_peak = peak_resolvers.load(Ordering::SeqCst);
    assert_eq!(
        resolver_attempts.load(Ordering::SeqCst),
        1,
        "the blocked outage probe is shared by all twelve callers"
    );

    release_resolvers.store(true, Ordering::SeqCst);
    resolver_released.notify_waiters();
    let mut results = Vec::with_capacity(CALLERS);
    for caller in callers {
        results.push(caller.await.expect("bounded caller task completes"));
    }
    client.shutdown().await;

    let observed_timestamps = resolver_timestamps
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(
        !observed_timestamps.is_empty(),
        "recovery fixture records a resolver setup timestamp"
    );
    assert_eq!(
        observed_peak, 1,
        "one persistent pool must serialize recovery to one resolver probe during the shared cooldown"
    );
    assert!(
        results.into_iter().all(|result| matches!(
            result,
            Err(SessionConsumerClientError::Unavailable | SessionConsumerClientError::Deadline)
        )),
        "every caller terminates through the bounded typed recovery failure"
    );
    let gaps = observed_timestamps
        .windows(2)
        .map(|window| window[1].duration_since(window[0]))
        .collect::<Vec<_>>();
    assert_eq!(
        gaps,
        [50_u64, 100, 200, 400, 400]
            .into_iter()
            .map(Duration::from_millis)
            .collect::<Vec<_>>(),
        "one pool publishes exact shared 50/100/200/400ms exponential recovery edges"
    );
}

#[tokio::test(start_paused = true)]
async fn credential_epoch_supersedes_blocked_pool_recovery_without_waiting_for_setup_deadline() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("superseded-recovery-server");
    let client_spiffe = spiffe("superseded-recovery-client");
    let (_authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let resolver_attempts = Arc::new(AtomicUsize::new(0));
    let active_resolvers = Arc::new(AtomicUsize::new(0));
    let peak_resolvers = Arc::new(AtomicUsize::new(0));
    let first_entered = Arc::new(AtomicBool::new(false));
    let first_dropped = Arc::new(AtomicBool::new(false));
    let second_saw_first_dropped = Arc::new(AtomicBool::new(false));
    let resolver: RemoteAddrResolver = {
        let resolver_attempts = Arc::clone(&resolver_attempts);
        let active_resolvers = Arc::clone(&active_resolvers);
        let peak_resolvers = Arc::clone(&peak_resolvers);
        let first_entered = Arc::clone(&first_entered);
        let first_dropped = Arc::clone(&first_dropped);
        let second_saw_first_dropped = Arc::clone(&second_saw_first_dropped);
        Arc::new(move || {
            let resolver_attempts = Arc::clone(&resolver_attempts);
            let active_resolvers = Arc::clone(&active_resolvers);
            let peak_resolvers = Arc::clone(&peak_resolvers);
            let first_entered = Arc::clone(&first_entered);
            let first_dropped = Arc::clone(&first_dropped);
            let second_saw_first_dropped = Arc::clone(&second_saw_first_dropped);
            Box::pin(async move {
                let ordinal = resolver_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                let _activity = ResolverAttemptGuard::enter(
                    active_resolvers,
                    peak_resolvers.as_ref(),
                    Arc::clone(&first_dropped),
                    ordinal,
                );
                if ordinal == 1 {
                    first_entered.store(true, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                    unreachable!("the stale resolver is cancelled by the fresh epoch");
                }
                second_saw_first_dropped
                    .store(first_dropped.load(Ordering::SeqCst), Ordering::SeqCst);
                Err(std::io::Error::other(
                    "fresh-epoch test resolver unavailable",
                ))
            })
        })
    };
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::try_from("persistent-consumer.test.invalid")
            .expect("test server name"),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(2));
    let client = PersistentSessionConsumerClient::try_from_stateless(
        stateless,
        PersistentSessionConsumerConfig::try_new(
            2,
            0,
            Duration::from_millis(250),
            1,
            Duration::from_millis(1_500),
            1,
            Duration::ZERO,
            Duration::from_secs(1),
        )
        .expect("fixed supersession config"),
    )
    .expect("persistent client");
    let first_client = client.clone();
    let first = tokio::spawn(async move { first_client.capabilities().await });
    for _ in 0..128 {
        if first_entered.load(Ordering::SeqCst) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        first_entered.load(Ordering::SeqCst),
        "the first epoch owns the blocked resolver setup"
    );

    client
        .request_reauthentication()
        .expect("publish a fresh credential epoch");
    let fresh_epoch_started_at = tokio::time::Instant::now();
    let second_client = client.clone();
    let second = tokio::spawn(async move { second_client.capabilities().await });
    for _ in 0..128 {
        if resolver_attempts.load(Ordering::SeqCst) >= 2 {
            break;
        }
        tokio::task::yield_now().await;
    }

    assert_eq!(
        resolver_attempts.load(Ordering::SeqCst),
        2,
        "the fresh epoch must begin without waiting for the stale setup deadline"
    );
    assert_eq!(
        tokio::time::Instant::now(),
        fresh_epoch_started_at,
        "credential supersession consumes no virtual setup time"
    );
    assert!(
        first_dropped.load(Ordering::SeqCst),
        "the stale resolver future is cancelled before the fresh setup begins"
    );
    assert!(
        second_saw_first_dropped.load(Ordering::SeqCst),
        "the serial permit transfers only after stale setup cancellation"
    );
    assert_eq!(
        peak_resolvers.load(Ordering::SeqCst),
        1,
        "credential supersession preserves one pool-wide recovery probe"
    );
    assert!(matches!(
        first.await.expect("stale caller task completes"),
        Err(SessionConsumerClientError::Deadline)
    ));
    assert!(matches!(
        second.await.expect("fresh caller task completes"),
        Err(SessionConsumerClientError::Unavailable)
    ));
    client.shutdown().await;
}

#[tokio::test]
async fn prewarm_opens_fixed_lanes_reuses_them_and_keeps_diagnostics_redacted() {
    const LANES: usize = 3;
    let pki = TestPki::new();
    let server_spiffe = spiffe("prewarm-server");
    let client_spiffe = spiffe("prewarm-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let (handle, upstream) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind counting proxy");
    let proxy = listener.local_addr().expect("proxy address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let proxy_task = {
        let accepted = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let (mut downstream, _) = listener.accept().await.expect("accept client");
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let Ok(mut upstream_stream) = tokio::net::TcpStream::connect(upstream).await
                    else {
                        return;
                    };
                    let _ =
                        tokio::io::copy_bidirectional(&mut downstream, &mut upstream_stream).await;
                });
            }
        })
    };
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(proxy) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(proxy.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(LANES, 8, 1),
    );
    let request_id_canary = SessionConsumerRequestId::from_bytes([0xa5; 16]);
    let scope_debug_canary = format!("{scope:?}");
    let scope_wire_canary = serde_json::to_string(&scope).expect("scope canary encodes");
    let request_id_debug_canary = format!("{request_id_canary:?}");
    let request_id_wire_canary = serde_json::to_string(&request_id_canary)
        .expect("request-id canary encodes")
        .trim_matches('"')
        .to_owned();
    let privacy_canaries = [
        "127.0.0.1",
        server_spiffe.as_str(),
        client_spiffe.as_str(),
        "prewarm-server",
        "prewarm-client",
        scope_debug_canary.as_str(),
        scope_wire_canary.as_str(),
        request_id_debug_canary.as_str(),
        request_id_wire_canary.as_str(),
    ];

    let initial_diagnostics = client.diagnostics().await;
    assert_fixed_zero_diagnostics(initial_diagnostics);
    let diagnostics_debug = format!("{initial_diagnostics:?}");
    for canary in privacy_canaries {
        assert!(
            !diagnostics_debug.contains(canary),
            "fixed numeric diagnostics must not render endpoint, identity, scope, or request data"
        );
    }

    assert_eq!(
        client
            .prewarm()
            .await
            .expect("prewarm")
            .ready_request_connections,
        LANES
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        LANES,
        "prewarm opens exactly the fixed lane count"
    );
    assert_eq!(
        service.calls.load(Ordering::SeqCst),
        0,
        "prewarm authenticates capacity without application traffic"
    );
    let mut warm_call_micros = Vec::with_capacity(16);
    for _ in 0..16 {
        let call_started = Instant::now();
        assert_eq!(client.capabilities().await, Ok(transported_capabilities()));
        warm_call_micros.push(call_started.elapsed().as_micros());
    }
    println!("synthetic_warm_call_samples_micros={warm_call_micros:?}");
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        LANES,
        "serial warm calls reuse authenticated lanes"
    );
    let diagnostics = client.diagnostics().await;
    assert_eq!(diagnostics.setup_successes, LANES as u64);
    assert_eq!(
        diagnostics.active, LANES as u64,
        "active counts authenticated physical request lanes, including idle lanes"
    );
    assert_eq!(
        diagnostics.max_active, LANES as u64,
        "maximum active records the exact prewarmed physical population"
    );
    assert_eq!(diagnostics.idle, LANES as u64);
    assert!(diagnostics.reused >= 16);
    let debug = format!("{client:?}");
    for canary in privacy_canaries {
        assert!(
            !debug.contains(canary),
            "persistent client Debug must not render endpoint, identity, scope, or request data"
        );
    }

    let report = client.shutdown().await;
    assert_eq!(report.drained_calls, 0);
    assert_eq!(report.forced_calls, 0);
    assert_eq!(
        client.diagnostics().await.active,
        0,
        "shutdown physically retires every idle request lane"
    );
    proxy_task.abort();
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn persistent_pools_derived_from_one_stateless_lineage_share_physical_admission() {
    const PHYSICAL_CAP: usize = 16;
    let pki = TestPki::new();
    let server_spiffe = spiffe("lineage-cap-server");
    let client_spiffe = spiffe("lineage-cap-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let (handle, upstream) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(64)
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start lineage-cap listener");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind counting proxy");
    let proxy = listener.local_addr().expect("proxy address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let proxy_task = {
        let accepted = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let (mut downstream, _) = listener.accept().await.expect("accept consumer TCP");
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let Ok(mut upstream_stream) = tokio::net::TcpStream::connect(upstream).await
                    else {
                        return;
                    };
                    let _ =
                        tokio::io::copy_bidirectional(&mut downstream, &mut upstream_stream).await;
                });
            }
        })
    };
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(proxy) }));
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(proxy.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(2));
    let mut holding_pools = Vec::with_capacity(PHYSICAL_CAP);
    for _ in 0..PHYSICAL_CAP {
        let pool =
            PersistentSessionConsumerClient::try_from_stateless(stateless.clone(), config(1, 0, 1))
                .expect("holding persistent pool");
        assert_eq!(
            pool.prewarm()
                .await
                .expect("sequential prewarm reaches one physical lane")
                .ready_request_connections,
            1
        );
        holding_pools.push(pool);
    }
    let second_pool =
        PersistentSessionConsumerClient::try_from_stateless(stateless, config(1, 0, 1))
            .expect("second persistent pool");

    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP);
    assert_eq!(service.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        second_pool.prewarm().await,
        Err(SessionConsumerClientError::Overloaded),
        "a second pool from one stateless clone lineage cannot exceed its fixed physical cap"
    );
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP);
    holding_pools
        .pop()
        .expect("one holding pool")
        .shutdown()
        .await;
    assert_eq!(
        second_pool
            .prewarm()
            .await
            .expect("releasing the first pool admits a fresh connection")
            .ready_request_connections,
        1
    );
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP + 1);

    for pool in holding_pools {
        pool.shutdown().await;
    }
    second_pool.shutdown().await;
    proxy_task.abort();
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn persistent_watch_preserves_typed_overload_from_shared_physical_admission() {
    const PHYSICAL_CAP: usize = 16;
    let pki = TestPki::new();
    let server_spiffe = spiffe("lineage-watch-cap-server");
    let client_spiffe = spiffe("lineage-watch-cap-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let (handle, upstream) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(64)
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start lineage-watch-cap listener");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind counting proxy");
    let proxy = listener.local_addr().expect("proxy address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let proxy_task = {
        let accepted = Arc::clone(&accepted);
        let active = Arc::clone(&active);
        tokio::spawn(async move {
            loop {
                let (mut downstream, _) = listener.accept().await.expect("accept consumer TCP");
                accepted.fetch_add(1, Ordering::SeqCst);
                active.fetch_add(1, Ordering::SeqCst);
                let active = Arc::clone(&active);
                tokio::spawn(async move {
                    if let Ok(mut upstream_stream) = tokio::net::TcpStream::connect(upstream).await
                    {
                        let _ =
                            tokio::io::copy_bidirectional(&mut downstream, &mut upstream_stream)
                                .await;
                    }
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        })
    };
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(proxy) }));
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(proxy.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(2));
    let persistent =
        PersistentSessionConsumerClient::try_from_stateless(stateless.clone(), config(1, 0, 1))
            .expect("persistent client");

    let mut held = Vec::with_capacity(PHYSICAL_CAP);
    for _ in 0..PHYSICAL_CAP {
        held.push(
            stateless
                .watch(0)
                .await
                .expect("stateless watch reaches shared physical cap"),
        );
    }
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP);
    assert_eq!(active.load(Ordering::SeqCst), PHYSICAL_CAP);
    assert_eq!(service.calls.load(Ordering::SeqCst), PHYSICAL_CAP);

    assert!(matches!(
        persistent.open_watch(0).await,
        Err(SessionConsumerClientError::Overloaded)
    ));
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP);
    assert_eq!(service.calls.load(Ordering::SeqCst), PHYSICAL_CAP);
    let overloaded = persistent.diagnostics().await;
    assert_eq!(overloaded.setup_attempts, 1);
    assert_eq!(overloaded.setup_failures, 1);
    assert_eq!(overloaded.failures, 1);
    assert_eq!(overloaded.not_transmitted, 1);
    assert_eq!(overloaded.overload, 1);
    assert_eq!(overloaded.watch_active, 0);

    drop(held.pop().expect("one held stateless watch"));
    tokio::time::timeout(Duration::from_secs(1), async {
        while active.load(Ordering::SeqCst) == PHYSICAL_CAP {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reader-owned physical watch permit is released within the fixed bound");
    let replacement = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match persistent.open_watch(0).await {
                Ok(watch) => break watch,
                Err(SessionConsumerClientError::Overloaded) => tokio::task::yield_now().await,
                Err(error) => panic!("replacement watch failed outside overload: {error}"),
            }
        }
    })
    .await
    .expect("released physical capacity becomes observable within the fixed bound");
    assert_eq!(accepted.load(Ordering::SeqCst), PHYSICAL_CAP + 1);
    assert_eq!(service.calls.load(Ordering::SeqCst), PHYSICAL_CAP + 1);

    drop(replacement);
    drop(held);
    persistent.shutdown().await;
    proxy_task.abort();
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn lane_retires_before_the_4097th_call_and_correlation_restarts_on_replacement() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("rollover-server");
    let client_spiffe = spiffe("rollover-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );

    client.prewarm().await.expect("prewarm one lane");
    for _ in 0..=opc_session_net::MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION {
        assert_eq!(client.capabilities().await, Ok(transported_capabilities()));
    }
    let diagnostics = client.diagnostics().await;
    assert_eq!(
        diagnostics.setup_successes, 2,
        "the call after the fixed correlation window uses one replacement lane"
    );
    assert_eq!(diagnostics.idle, 1);
    assert!(diagnostics.reconnects >= 1);
    assert_eq!(
        service.calls.load(Ordering::SeqCst),
        opc_session_net::MAX_SESSION_QUORUM_CONSUMER_REQUESTS_PER_CONNECTION + 1
    );

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn one_lane_dispatches_twelve_bounded_waiters_in_admission_order() {
    const WAITERS: usize = 12;
    let pki = TestPki::new();
    let server_spiffe = spiffe("fair-server");
    let client_spiffe = spiffe("fair-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.arm_blocks(1);
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, WAITERS, 1),
    );

    let request_ids = (0..=WAITERS)
        .map(|index| {
            opc_session_store::SessionConsumerRequestId::from_bytes(
                [u8::try_from(index + 1).expect("bounded test index"); 16],
            )
        })
        .collect::<Vec<_>>();
    let first = {
        let client = client.clone();
        let request_id = request_ids[0];
        tokio::spawn(async move {
            let request = SessionConsumerRequest::new(
                scope,
                request_id,
                SessionConsumerOperation::Capabilities,
            );
            client.execute(&request).await
        })
    };
    service.wait_until_entered(1).await;

    let mut queued = Vec::with_capacity(WAITERS);
    for (index, request_id) in request_ids.iter().copied().skip(1).enumerate() {
        let queued_client = client.clone();
        queued.push(tokio::spawn(async move {
            let request = SessionConsumerRequest::new(
                scope,
                request_id,
                SessionConsumerOperation::Capabilities,
            );
            queued_client.execute(&request).await
        }));
        tokio::time::timeout(Duration::from_secs(1), async {
            while client.diagnostics().await.queued < (index + 1) as u64 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("caller reaches the bounded fair lane queue");
    }

    service.release();
    assert!(first.await.expect("first task").is_ok());
    for caller in queued {
        assert!(caller.await.expect("queued task").is_ok());
    }
    assert!(
        service.request_order() == request_ids,
        "the bounded lane semaphore must preserve admission order"
    );
    assert_eq!(client.diagnostics().await.pool_wait_max, WAITERS as u64);

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn queued_lane_waiter_cannot_be_overtaken_by_late_callers() {
    const LATE_CALLERS: usize = 16;
    let pki = TestPki::new();
    let server_spiffe = spiffe("no-barge-server");
    let client_spiffe = spiffe("no-barge-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.arm_blocks(1);
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, LATE_CALLERS + 1, 1),
    );

    let first_id = SessionConsumerRequestId::from_bytes([1; 16]);
    let queued_id = SessionConsumerRequestId::from_bytes([2; 16]);
    let first = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .execute(&SessionConsumerRequest::new(
                    scope,
                    first_id,
                    SessionConsumerOperation::Capabilities,
                ))
                .await
        })
    };
    service.wait_until_entered(1).await;
    let queued = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .execute(&SessionConsumerRequest::new(
                    scope,
                    queued_id,
                    SessionConsumerOperation::Capabilities,
                ))
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        while client.diagnostics().await.queued != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the first late-sensitive caller reaches the FIFO lane queue");

    let late = (0..LATE_CALLERS)
        .map(|index| {
            let client = client.clone();
            tokio::spawn(async move {
                let request_id = SessionConsumerRequestId::from_bytes(
                    [u8::try_from(index + 3).expect("bounded late caller index"); 16],
                );
                client
                    .execute(&SessionConsumerRequest::new(
                        scope,
                        request_id,
                        SessionConsumerOperation::Capabilities,
                    ))
                    .await
            })
        })
        .collect::<Vec<_>>();
    service.release();

    assert!(first.await.expect("first caller task").is_ok());
    assert!(queued.await.expect("queued caller task").is_ok());
    for caller in late {
        assert!(caller.await.expect("late caller task").is_ok());
    }
    assert_eq!(
        service.request_order().get(1),
        Some(&queued_id),
        "a caller queued before release must dispatch before every late arrival"
    );

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn pool_admission_consumes_the_original_complete_operation_deadline() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("admission-deadline-server");
    let client_spiffe = spiffe("admission-deadline-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.arm_blocks(1);
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_operation_timeout(Duration::from_millis(240));
    let client = PersistentSessionConsumerClient::try_from_stateless(stateless, config(1, 1, 1))
        .expect("persistent client");
    client.prewarm().await.expect("prewarm the sole lane");

    let first = {
        let client = client.clone();
        tokio::spawn(async move { client.capabilities().await })
    };
    service.wait_until_entered(1).await;
    let queued = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .execute(&SessionConsumerRequest::new(
                    scope,
                    SessionConsumerRequestId::from_bytes([3; 16]),
                    SessionConsumerOperation::Capabilities,
                ))
                .await
        })
    };
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), queued)
            .await
            .expect("the original operation deadline bounds lane admission")
            .expect("queued caller task"),
        Err(PersistentSessionConsumerExecuteError::NotTransmitted {
            cause: SessionConsumerClientError::Deadline,
        })
    );
    assert_eq!(
        service.calls.load(Ordering::SeqCst),
        1,
        "a lane-admission deadline cannot dispatch a second request"
    );

    service.release();
    let _ = first.await.expect("first caller task");
    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn persistent_watch_zero_cursor_normalizes_to_the_first_committed_sequence() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("zero-watch-server");
    let client_spiffe = spiffe("zero-watch-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.emit_watch_entries_then_close(small_watch_change_at(1), 1);
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );

    let mut watch = client.open_watch(0).await.expect("open zero cursor watch");
    let entry = tokio::time::timeout(Duration::from_secs(1), watch.next())
        .await
        .expect("the normalized first entry arrives")
        .expect("watch remains open for the first entry")
        .expect("zero cursor accepts sequence one");
    assert_eq!(entry.sequence(), 1);

    drop(watch);
    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn slow_lane_does_not_serialize_sixteen_callers_and_watch_capacity_is_isolated() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("parallel-server");
    let client_spiffe = spiffe("parallel-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(4, 16, 1),
    );
    client.prewarm().await.expect("prewarm");

    service.arm_blocks(1);
    let slow = {
        let client = client.clone();
        tokio::spawn(async move { client.capabilities().await })
    };
    service.wait_until_entered(1).await;
    let callers = (0..15)
        .map(|_| {
            let client = client.clone();
            tokio::spawn(async move { client.capabilities().await })
        })
        .collect::<Vec<_>>();
    // Only the first of the sixteen calls is held. Prove other request
    // capacity reaches dispatch before releasing it; this is deterministic
    // evidence that clones are not globally serialized behind the slow call.
    tokio::time::timeout(Duration::from_millis(250), service.wait_until_entered(4))
        .await
        .expect("other request capacity dispatches while one lane remains slow");
    assert!(
        !slow.is_finished(),
        "the deliberately slow lane is still held"
    );
    service.release();
    for (index, caller) in callers.into_iter().enumerate() {
        let result = tokio::time::timeout(Duration::from_millis(800), caller)
            .await
            .expect("unblocked caller must not serialize behind slow lane")
            .expect("caller task");
        assert_eq!(
            result,
            Ok(transported_capabilities()),
            "caller {index} failed; diagnostics={:?}",
            client.diagnostics().await,
        );
    }
    assert_eq!(service.calls.load(Ordering::SeqCst), 16);
    assert_eq!(
        slow.await.expect("slow task"),
        Ok(transported_capabilities())
    );

    let watch = client
        .open_watch(0)
        .await
        .expect("first isolated watch slot");
    assert_eq!(client.capabilities().await, Ok(transported_capabilities()));
    assert!(matches!(
        client.open_watch(0).await,
        Err(SessionConsumerClientError::Overloaded)
    ));
    drop(watch);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if client.diagnostics().await.watch_active == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dropping the receiver stops its reader and releases the watch slot");
    let replacement_watch = client
        .open_watch(0)
        .await
        .expect("dropping a watch releases only its watch slot");
    drop(replacement_watch);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if client.diagnostics().await.watch_active == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dropping the replacement receiver releases its watch slot");
    let diagnostics = client.diagnostics().await;
    assert!(diagnostics.max_active >= 2);
    assert_eq!(diagnostics.max_watch_active, 1);
    let report = client.shutdown().await;
    assert_eq!(report.drained_watches, 0);
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn admitted_call_drains_across_rotation_and_hard_deadline_releases_its_lane() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("drain-server");
    let client_spiffe = spiffe("drain-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let lifecycle = ConnectionLifecyclePolicy::try_new(
        Duration::from_secs(2),
        Duration::from_millis(100),
        Duration::from_millis(1),
        Duration::from_millis(1),
        Duration::ZERO,
    )
    .expect("short deterministic drain policy");
    let server_rotation = SessionReauthenticationControl::new();
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_connection_lifecycle(lifecycle)
    .with_reauthentication_control(server_rotation.clone())
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(1))
    .with_connection_lifecycle(lifecycle);
    let client = PersistentSessionConsumerClient::try_from_stateless(stateless, config(1, 0, 1))
        .expect("persistent client");
    client.prewarm().await.expect("initial prewarm");

    service.arm_blocks(1);
    let completing_id = opc_session_store::SessionConsumerRequestId::new();
    let completing = {
        let client = client.clone();
        tokio::spawn(async move {
            let request = SessionConsumerRequest::new(
                scope,
                completing_id,
                SessionConsumerOperation::Capabilities,
            );
            client.execute(&request).await
        })
    };
    service.wait_until_entered(1).await;
    assert!(
        !client.readiness().await.ready,
        "a leased request lane is not idle authenticated readiness"
    );
    client
        .request_reauthentication()
        .expect("begin graceful connection drain");
    server_rotation
        .request_reauthentication()
        .expect("begin graceful server drain");
    service.release();
    assert_eq!(
        completing.await.expect("completing task"),
        Ok(SessionConsumerResponse::Capabilities(
            transported_capabilities()
        )),
        "already-admitted work may finish inside the rotation drain window"
    );

    assert!(client.prewarm().await.expect("replacement prewarm").ready);
    service.arm_blocks(1);
    let forced_id = opc_session_store::SessionConsumerRequestId::new();
    let forced = {
        let client = client.clone();
        tokio::spawn(async move {
            let request = SessionConsumerRequest::new(
                scope,
                forced_id,
                SessionConsumerOperation::Capabilities,
            );
            client.execute(&request).await
        })
    };
    service.wait_until_entered(2).await;
    let drain_started = Instant::now();
    client
        .request_reauthentication()
        .expect("begin bounded hard drain");
    server_rotation
        .request_reauthentication()
        .expect("begin bounded server hard drain");
    let error = tokio::time::timeout(Duration::from_millis(500), forced)
        .await
        .expect("hard deadline bounds the active call")
        .expect("forced task")
        .expect_err("hard retirement makes the read unavailable");
    assert!(
        matches!(
            error,
            PersistentSessionConsumerExecuteError::ReadUnavailable {
                cause: SessionConsumerClientError::Deadline,
            }
        ),
        "post-write read retirement remains retryable and never claims mutation ambiguity"
    );
    assert!(drain_started.elapsed() >= Duration::from_millis(75));
    assert_eq!(client.diagnostics().await.active, 0);
    assert_eq!(service.calls.load(Ordering::SeqCst), 2, "no blind replay");
    service.release();

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn byte_saturated_watch_queue_terminalizes_without_rotation_or_caller_polling() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("watch-drain-server");
    let client_spiffe = spiffe("watch-drain-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.emit_watch_entries_then_pending(large_watch_change(), 2);
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(2)
    .with_operation_timeout(Duration::from_secs(2))
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start single-slot consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );

    let mut stale_watch = client.open_watch(0).await.expect("open pressure watch");
    tokio::time::timeout(Duration::from_millis(250), async {
        while client.diagnostics().await.watch_active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("byte admission failure releases the watch slot without rotation or polling");
    let replacement = client
        .open_watch(0)
        .await
        .expect("released isolated slot admits a replacement watch");
    drop(replacement);
    assert!(stale_watch
        .next()
        .await
        .expect("the already-buffered large item remains ordered")
        .is_ok());
    assert!(matches!(
        stale_watch.next().await,
        Some(Err(opc_session_store::StoreError::BackendUnavailable(_)))
    ));
    assert!(stale_watch.next().await.is_none());

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn endpoint_loss_at_exact_watch_byte_saturation_releases_without_reconnect() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("watch-exact-byte-loss-server");
    let client_spiffe = spiffe("watch-exact-byte-loss-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.emit_watch_entries_then_close(exact_watch_byte_budget_change(), 1);
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(2)
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start exact-byte consumer listener");
    let resolutions = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&resolutions);
    let resolver: RemoteAddrResolver = Arc::new(move || {
        counted.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(address) })
    });
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );

    let mut watch = client.open_watch(0).await.expect("open exact-byte watch");
    tokio::time::timeout(Duration::from_secs(1), async {
        service.wait_for_watch_emissions(1).await;
        while client.diagnostics().await.watch_active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("endpoint loss releases the byte-saturated isolated lease");
    assert_eq!(
        resolutions.load(Ordering::SeqCst),
        1,
        "a saturated unpolled queue never starts replacement setup"
    );
    assert!(watch
        .next()
        .await
        .expect("exact-cap item remains ordered")
        .is_ok());
    assert!(matches!(
        watch.next().await,
        Some(Err(opc_session_store::StoreError::BackendUnavailable(_)))
    ));
    assert!(watch.next().await.is_none());

    let replacement = client
        .open_watch(0)
        .await
        .expect("released slot admits one explicit replacement");
    drop(replacement);
    assert_eq!(resolutions.load(Ordering::SeqCst), 2);
    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn sixty_fifth_item_terminalizes_an_unpolled_full_watch_queue() {
    const WATCH_QUEUE_ITEMS: usize = 64;
    let pki = TestPki::new();
    let server_spiffe = spiffe("watch-small-queue-server");
    let client_spiffe = spiffe("watch-small-queue-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.emit_watch_entries_then_pending(small_watch_change(), WATCH_QUEUE_ITEMS + 1);
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(2)
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );

    let mut stale_watch = client.open_watch(0).await.expect("open queued watch");
    tokio::time::timeout(Duration::from_secs(1), async {
        // Wait on the producer's exact finite emission edge rather than
        // sleeping while i686 is still scheduling authenticated watch setup.
        service
            .wait_for_watch_emissions(WATCH_QUEUE_ITEMS + 1)
            .await;
        while client.diagnostics().await.watch_active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the 65th item releases the unpolled fixed watch lease");
    let replacement = client
        .open_watch(0)
        .await
        .expect("released slot admits a replacement watch");
    drop(replacement);
    for expected_sequence in 1..=WATCH_QUEUE_ITEMS as u64 {
        assert_eq!(
            stale_watch
                .next()
                .await
                .expect("buffered item precedes rotation terminal")
                .expect("buffered item remains valid")
                .sequence(),
            expected_sequence,
        );
    }
    assert!(matches!(
        stale_watch.next().await,
        Some(Err(opc_session_store::StoreError::BackendUnavailable(_)))
    ));
    assert!(stale_watch.next().await.is_none());

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn wrapped_watch_item_one_byte_over_the_local_cap_is_terminal_not_eof() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("watch-envelope-cap-server");
    let client_spiffe = spiffe("watch-envelope-cap-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let edge = watch_result_envelope_edge_change();
    let actual = serde_json::to_vec(&Ok::<_, SessionConsumerStoreError>(edge.clone()))
        .expect("queued edge item encodes")
        .len();
    service.emit_one_watch_entry_then_pending(edge);
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(2)
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );

    let mut watch = client.open_watch(0).await.expect("open edge watch");
    tokio::time::timeout(Duration::from_millis(250), async {
        while client.diagnostics().await.watch_active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("oversized queued representation releases the watch lease");
    assert!(matches!(
        watch.next().await,
        Some(Err(opc_session_store::StoreError::PayloadTooLarge {
            actual: observed,
            max: 524_288,
        })) if observed == actual
    ));
    assert!(watch.next().await.is_none());
    assert_eq!(service.watch_starts(), vec![1]);
    let replacement = client.open_watch(0).await.expect("slot was released");
    drop(replacement);
    assert_eq!(service.watch_starts(), vec![1, 1]);

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn maximum_watch_sequence_is_delivered_once_then_closes_cleanly() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("watch-max-sequence-server");
    let client_spiffe = spiffe("watch-max-sequence-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.emit_watch_entries_then_close(small_watch_change_at(u64::MAX), 1);
    let (handle, address) =
        SessionQuorumConsumerServer::new(service, pki.server_config(&server_spiffe), authorizer)
            .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
            .await
            .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );

    let mut watch = client
        .open_watch(u64::MAX)
        .await
        .expect("open terminal watch");
    assert_eq!(
        watch
            .next()
            .await
            .expect("terminal sequence item")
            .expect("valid item")
            .sequence(),
        u64::MAX,
    );
    assert!(watch.next().await.is_none());
    let diagnostics = client.diagnostics().await;
    assert_eq!(diagnostics.reconnects, 0);
    assert_eq!(diagnostics.watch_active, 0);

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn terminal_watch_error_and_eof_never_advance_the_persistent_cursor() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("watch-error-cursor-server");
    let client_spiffe = spiffe("watch-error-cursor-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.emit_terminal_watch_error(SessionConsumerStoreError::WatchCatchUpRequired);
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );

    let mut watch = client.open_watch(0).await.expect("open watch");
    assert_eq!(
        watch.next().await.expect("terminal typed watch item"),
        Err(opc_session_store::StoreError::ReplicationWatchCatchUpRequired),
    );
    assert!(watch.next().await.is_none(), "peer EOF remains terminal");
    assert_eq!(client.diagnostics().await.reconnects, 0);

    // The explicit next watch is a fresh caller decision. It still normalizes
    // zero to the inclusive first sequence, proving the peer error did not
    // consume or skip an authoritative change.
    let replacement = client.open_watch(0).await.expect("fresh watch");
    drop(replacement);
    assert_eq!(service.watch_starts(), vec![1, 1]);

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn cancelled_watch_reconnect_has_one_terminal_setup_outcome() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("watch-reconnect-cancel-server");
    let client_spiffe = spiffe("watch-reconnect-cancel-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.emit_watch_entries_then_close(small_watch_change_at(1), 1);
    let (handle, address) =
        SessionQuorumConsumerServer::new(service, pki.server_config(&server_spiffe), authorizer)
            .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
            .await
            .expect("start consumer listener");

    let resolutions = Arc::new(AtomicUsize::new(0));
    let reconnect_started = Arc::new(Notify::new());
    let resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        let reconnect_started = Arc::clone(&reconnect_started);
        Arc::new(move || {
            let attempt = resolutions.fetch_add(1, Ordering::SeqCst);
            let reconnect_started = Arc::clone(&reconnect_started);
            Box::pin(async move {
                if attempt == 0 {
                    Ok(address)
                } else {
                    reconnect_started.notify_one();
                    std::future::pending::<std::io::Result<SocketAddr>>().await
                }
            })
        })
    };
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );

    let mut watch = client.open_watch(1).await.expect("open watch");
    assert_eq!(
        watch
            .next()
            .await
            .expect("first watch item")
            .expect("valid first watch item")
            .sequence(),
        1,
    );
    tokio::time::timeout(Duration::from_secs(1), reconnect_started.notified())
        .await
        .expect("replacement setup reaches the resolver");
    drop(watch);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let diagnostics = client.diagnostics().await;
            if diagnostics.watch_active == 0
                && diagnostics.setup_attempts
                    == diagnostics.setup_successes + diagnostics.setup_failures
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("stream cancellation terminates the in-flight replacement setup");
    let diagnostics = client.diagnostics().await;
    assert_eq!(diagnostics.setup_attempts, 2);
    assert_eq!(diagnostics.setup_successes, 1);
    assert_eq!(diagnostics.setup_failures, 1);

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn watch_open_without_item_has_one_paced_bounded_recovery_window() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("watch-no-progress-server");
    let client_spiffe = spiffe("watch-no-progress-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.close_watch_without_item();
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start no-progress consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );

    let mut watch = client.open_watch(0).await.expect("initial WatchOpened");
    let terminal = tokio::time::timeout(Duration::from_secs(1), watch.next())
        .await
        .expect("bounded no-progress recovery terminates")
        .expect("bounded no-progress recovery reports one terminal item");
    assert!(matches!(
        terminal,
        Err(opc_session_store::StoreError::BackendUnavailable(_))
    ));
    assert!(watch.next().await.is_none());
    assert_eq!(service.watch_starts(), vec![1, 1, 1]);
    let started_at = service.watch_started_at();
    assert_eq!(started_at.len(), 3);
    assert!(
        started_at[1].duration_since(started_at[0]) >= Duration::from_millis(50),
        "the first successful-but-empty reopen cannot bypass recovery pacing"
    );
    assert!(
        started_at[2].duration_since(started_at[1]) >= Duration::from_millis(50),
        "the second successful-but-empty reopen retains the same watch-level budget"
    );

    for _ in 0..1_000 {
        if client.diagnostics().await.watch_active == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    let diagnostics = client.diagnostics().await;
    assert_eq!(diagnostics.watch_active, 0);
    assert_eq!(diagnostics.reconnects, 2);
    assert_eq!(diagnostics.setup_attempts, 3);
    assert_eq!(diagnostics.setup_successes, 3);
    assert_eq!(diagnostics.setup_failures, 0);
    assert_eq!(
        diagnostics.setup_attempts,
        diagnostics.setup_successes + diagnostics.setup_failures
    );

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn persistent_watch_reconnects_at_the_exact_delivered_cursor_after_endpoint_loss() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("watch-reconnect-server");
    let client_spiffe = spiffe("watch-reconnect-client");
    let (first_authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let first_service = Arc::new(ControlledConsumer::default());
    first_service.arm_watch_block();
    first_service.emit_watch_entries_then_close(small_watch_change_at(1), 1);
    let (first_handle, first_address) = SessionQuorumConsumerServer::new(
        first_service.clone(),
        pki.server_config(&server_spiffe),
        first_authorizer,
    )
    .with_max_connections(1)
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("first listener address"),
    )
    .await
    .expect("start first consumer listener");

    let (second_authorizer, second_scope) = authorizer_and_scope(&client_spiffe).await;
    assert_eq!(scope, second_scope, "endpoint replacement retains scope");
    let second_service = Arc::new(ControlledConsumer::default());
    second_service.emit_watch_entries_then_close(small_watch_change_at(2), 1);
    let (second_handle, second_address) = SessionQuorumConsumerServer::new(
        second_service.clone(),
        pki.server_config(&server_spiffe),
        second_authorizer,
    )
    .with_max_connections(1)
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("second listener address"),
    )
    .await
    .expect("start replacement consumer listener");

    let resolved = Arc::new(RwLock::new(first_address));
    let resolutions = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolved = Arc::clone(&resolved);
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            let resolved = Arc::clone(&resolved);
            let resolutions = Arc::clone(&resolutions);
            Box::pin(async move {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Ok(*resolved.read().expect("resolver address lock"))
            })
        })
    };
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(first_address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );

    let mut watch = client.open_watch(1).await.expect("open first watch");
    first_service.wait_until_entered(1).await;
    *resolved.write().expect("resolver address lock") = second_address;
    first_service.release_watch();

    let first = tokio::time::timeout(Duration::from_secs(1), watch.next())
        .await
        .expect("first entry arrives before bounded reconnect")
        .expect("watch remains open")
        .expect("first entry is valid");
    let second = tokio::time::timeout(Duration::from_secs(1), watch.next())
        .await
        .expect("replacement entry arrives")
        .expect("watch remains open after endpoint replacement")
        .expect("replacement entry is valid");
    assert_eq!(first.sequence(), 1);
    assert_eq!(second.sequence(), 2);
    assert!(
        resolutions.load(Ordering::SeqCst) >= 2,
        "a reconnect refreshes the endpoint resolver"
    );
    // The replacement peer intentionally closes after sequence 2, so the
    // reader may already be attempting the next bounded replacement when the
    // caller receives that queued item. Closing the caller-visible stream is
    // the exact terminal event for that in-flight setup; wait for it before
    // asserting the completed-outcome accounting invariant.
    drop(watch);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let diagnostics = client.diagnostics().await;
            if diagnostics.watch_active == 0
                && diagnostics.setup_attempts
                    == diagnostics.setup_successes + diagnostics.setup_failures
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("closing the stream terminates any next replacement setup");
    let diagnostics = client.diagnostics().await;
    assert!(
        diagnostics.reconnects >= 1,
        "the bounded replacement is observable only as a fixed counter"
    );
    assert_eq!(
        diagnostics.setup_successes, 2,
        "the initial watch and its exact replacement each complete one authenticated setup"
    );
    assert_eq!(
        diagnostics.setup_attempts,
        diagnostics.setup_successes + diagnostics.setup_failures,
        "every completed sequential replacement setup has one terminal outcome"
    );

    client.shutdown().await;
    first_handle.abort_and_wait().await;
    second_handle.abort_and_wait().await;
}

#[tokio::test]
async fn persistent_watch_reconnects_after_authenticated_rotation() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("watch-rotation-server");
    let client_spiffe = spiffe("watch-rotation-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.emit_one_watch_entry_then_pending(small_watch_change_at(1));
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(1)
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("listener address"),
    )
    .await
    .expect("start consumer listener");
    let resolutions = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            let resolutions = Arc::clone(&resolutions);
            Box::pin(async move {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Ok(address)
            })
        })
    };
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );
    let mut watch = client.open_watch(1).await.expect("open rotation watch");
    let first = tokio::time::timeout(Duration::from_secs(1), watch.next())
        .await
        .expect("first entry arrives")
        .expect("watch remains open")
        .expect("first entry is valid");
    assert_eq!(first.sequence(), 1);

    client
        .request_reauthentication()
        .expect("retire the authenticated watch connection");
    let second = tokio::time::timeout(Duration::from_secs(1), watch.next())
        .await
        .expect("reconnected entry arrives")
        .expect("watch remains open after rotation")
        .expect("reconnected entry is valid");
    assert_eq!(second.sequence(), 2);
    assert!(
        resolutions.load(Ordering::SeqCst) >= 2,
        "rotation reconnects through the resolver rather than retaining stale transport"
    );

    drop(watch);
    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn peer_terminal_releases_an_unpolled_full_small_item_watch_queue() {
    const WATCH_QUEUE_ITEMS: usize = 64;
    let pki = TestPki::new();
    let server_spiffe = spiffe("watch-peer-terminal-server");
    let client_spiffe = spiffe("watch-peer-terminal-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.emit_watch_entries_then_close(small_watch_change(), WATCH_QUEUE_ITEMS);
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .with_max_connections(2)
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );

    let mut stale_watch = client.open_watch(0).await.expect("open finite watch");
    tokio::time::timeout(Duration::from_secs(1), async {
        while service.watch_emitted.load(Ordering::SeqCst) < WATCH_QUEUE_ITEMS {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("server emits exactly enough entries to fill the item queue");
    tokio::time::timeout(Duration::from_millis(500), async {
        while client.diagnostics().await.watch_active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("peer terminal releases the fixed watch lease without caller polling");

    // Keep `stale_watch` unpolled and alive while proving that its full local
    // queue cannot retain either the isolated watch slot or physical permit.
    let replacement = tokio::time::timeout(Duration::from_millis(500), client.open_watch(0))
        .await
        .expect("replacement watch admission remains bounded")
        .expect("released peer-terminal slot admits a replacement watch");
    assert!(service.calls.load(Ordering::SeqCst) >= 2);
    drop(replacement);
    for expected_sequence in 1..=WATCH_QUEUE_ITEMS as u64 {
        assert_eq!(
            stale_watch
                .next()
                .await
                .expect("buffered item precedes peer terminal")
                .expect("buffered item remains valid")
                .sequence(),
            expected_sequence,
        );
    }
    assert!(matches!(
        stale_watch.next().await,
        Some(Err(opc_session_store::StoreError::BackendUnavailable(_)))
    ));
    assert!(stale_watch.next().await.is_none());

    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn peer_eof_cancels_blocked_watch_setup_and_releases_isolated_slot() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("watch-setup-eof-server");
    let client_spiffe = spiffe("watch-setup-eof-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    service.arm_watch_setup_block();
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 1, 1),
    );

    let opening = {
        let client = client.clone();
        tokio::spawn(async move { client.open_watch(0).await })
    };
    tokio::time::timeout(
        Duration::from_millis(200),
        service.wait_until_watch_setup_entered(),
    )
    .await
    .expect("backend watch setup becomes active");
    opening.abort();
    assert!(
        opening.await.is_err(),
        "caller watch cancellation completes"
    );
    tokio::time::timeout(
        Duration::from_millis(200),
        service.wait_until_no_active_watch_setup(),
    )
    .await
    .expect("peer EOF promptly drops the backend watch-setup future");
    tokio::time::timeout(Duration::from_millis(200), async {
        while client.diagnostics().await.watch_active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("caller cancellation releases the isolated watch slot");

    service.release_watch_setup();
    let replacement = tokio::time::timeout(Duration::from_millis(500), client.open_watch(0))
        .await
        .expect("released watch slot admits a replacement")
        .expect("replacement watch opens");
    drop(replacement);
    client.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn saturation_cancellation_and_reauthentication_replace_only_stale_lanes() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("replacement-server");
    let client_spiffe = spiffe("replacement-client");
    let (first_authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let first_service = Arc::new(ControlledConsumer::default());
    let (first_handle, first_address) = SessionQuorumConsumerServer::new(
        first_service.clone(),
        pki.server_config(&server_spiffe),
        first_authorizer,
    )
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("first listen address"),
    )
    .await
    .expect("start first listener");
    let resolved = Arc::new(RwLock::new(first_address));
    let resolutions = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolved = Arc::clone(&resolved);
        let resolutions = Arc::clone(&resolutions);
        Arc::new(move || {
            let resolved = Arc::clone(&resolved);
            let resolutions = Arc::clone(&resolutions);
            Box::pin(async move {
                resolutions.fetch_add(1, Ordering::SeqCst);
                Ok(*resolved.read().expect("resolver address lock"))
            })
        })
    };
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(first_address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 1, 1),
    );
    client.prewarm().await.expect("one lane prewarm");

    first_service.arm_blocks(1);
    let active = {
        let client = client.clone();
        tokio::spawn(async move { client.capabilities().await })
    };
    first_service.wait_until_entered(1).await;
    assert!(
        !client.readiness().await.ready,
        "readiness must not count the checked-out lane as idle"
    );
    let queued = {
        let client = client.clone();
        tokio::spawn(async move { client.capabilities().await })
    };
    tokio::time::timeout(Duration::from_millis(200), async {
        while client.diagnostics().await.queued != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("second caller must occupy the bounded queue");
    let started = tokio::time::Instant::now();
    assert_eq!(
        client.capabilities().await,
        Err(SessionConsumerClientError::Overloaded)
    );
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "saturated admission fails promptly"
    );
    let before_queued_cancellation = client.diagnostics().await;
    queued.abort();
    assert!(queued.await.is_err(), "queued cancellation completes");
    tokio::time::timeout(Duration::from_millis(200), async {
        while client.diagnostics().await.queued != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("queued cancellation releases its FIFO admission record");
    let after_queued_cancellation = client.diagnostics().await;
    assert_eq!(
        after_queued_cancellation.failures,
        before_queued_cancellation.failures + 1,
        "one accepted queued call has exactly one terminal failure"
    );
    assert_eq!(
        after_queued_cancellation.not_transmitted,
        before_queued_cancellation.not_transmitted + 1,
        "queued cancellation is exactly one pre-write outcome"
    );
    assert_eq!(
        after_queued_cancellation.outcome_unknown, before_queued_cancellation.outcome_unknown,
        "queued cancellation never crosses the effect boundary"
    );
    active.abort();
    assert!(active.await.is_err(), "active cancellation completes");
    tokio::time::timeout(
        Duration::from_millis(200),
        first_service.wait_until_no_active_execute(),
    )
    .await
    .expect("peer EOF promptly cancels the bounded server execute future");
    tokio::time::timeout(Duration::from_millis(200), async {
        while client.diagnostics().await.queued != 0 || client.diagnostics().await.active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("caller cancellation releases admission and active bounds");
    first_service.release();
    assert_eq!(
        client.capabilities().await,
        Ok(transported_capabilities()),
        "released bounds admit a new call and retain an idle lane for reauthentication"
    );
    let after_cancellation = client.diagnostics().await;
    assert_eq!(
        after_cancellation.setup_successes, 2,
        "caller cancellation discards its checked-out lane and the next caller opens one replacement"
    );
    assert_eq!(
        after_cancellation.reconnects, 1,
        "caller cancellation records exactly one discarded-lane reconnect"
    );

    first_handle.abort_and_wait().await;
    let (second_authorizer, second_scope) = authorizer_and_scope(&client_spiffe).await;
    assert!(
        scope == second_scope,
        "replacement retains the exact consumer scope"
    );
    let second_service = Arc::new(ControlledConsumer::default());
    let (second_handle, second_address) = SessionQuorumConsumerServer::new(
        second_service.clone(),
        pki.server_config(&server_spiffe),
        second_authorizer,
    )
    .listen(
        "127.0.0.1:0"
            .parse::<SocketAddr>()
            .expect("second listen address"),
    )
    .await
    .expect("start replacement listener");
    *resolved.write().expect("resolver address lock") = second_address;
    client.request_reauthentication().expect("drain stale lane");
    assert_eq!(client.capabilities().await, Ok(transported_capabilities()));
    assert_eq!(second_service.calls.load(Ordering::SeqCst), 1);
    assert!(
        resolutions.load(Ordering::SeqCst) >= 2,
        "only a replacement connection resolves again"
    );
    let diagnostics = client.diagnostics().await;
    assert!(diagnostics.overload >= 1);
    assert!(diagnostics.reconnects >= 1);

    // An empty caller-visible queue remains recoverable across authenticated
    // rotation. The reader retains its one isolated lease while it reconnects;
    // a full or byte-blocked local queue is covered separately and fails
    // closed so an unpolled consumer cannot retain capacity forever.
    let stale_watch = client.open_watch(0).await.expect("open stale watch");
    let reconnects_before_watch_rotation = client.diagnostics().await.reconnects;
    client
        .request_reauthentication()
        .expect("retire unpolled watch transport");
    tokio::time::timeout(Duration::from_millis(250), async {
        while client.diagnostics().await.reconnects <= reconnects_before_watch_rotation {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("rotation reconnects the recoverable unpolled watch");
    assert_eq!(
        client.diagnostics().await.watch_active,
        1,
        "the reconnect retains exactly the original isolated watch lease"
    );
    drop(stale_watch);
    tokio::time::timeout(Duration::from_millis(250), async {
        while client.diagnostics().await.watch_active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("caller stream drop releases the reconnected watch slot");
    let replacement_watch = client
        .open_watch(0)
        .await
        .expect("released watch slot admits a replacement watch");
    drop(replacement_watch);
    let report = client.shutdown().await;
    assert_eq!(report.drained_calls, 0);
    second_handle.abort_and_wait().await;
}

#[tokio::test]
async fn forced_shutdown_stops_admission_and_bounds_active_calls_and_watches() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("shutdown-server");
    let client_spiffe = spiffe("shutdown-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 1, 1),
    );
    service.arm_blocks(1);
    let active = {
        let client = client.clone();
        tokio::spawn(async move { client.capabilities().await })
    };
    service.wait_until_entered(1).await;
    let watch = client.open_watch(0).await.expect("open pending watch");
    let report = tokio::time::timeout(Duration::from_millis(1_500), client.shutdown())
        .await
        .expect("shutdown drain is bounded");
    assert!(report.forced_calls >= 1);
    assert!(report.forced_watches >= 1);
    assert_eq!(
        client.capabilities().await,
        Err(SessionConsumerClientError::ShuttingDown)
    );
    drop(watch);
    active.abort();
    let _ = active.await;
    service.release();
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn cancelled_shutdown_future_still_forces_and_releases_a_quiet_watch() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("cancelled-shutdown-server");
    let client_spiffe = spiffe("cancelled-shutdown-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let (handle, address) =
        SessionQuorumConsumerServer::new(service, pki.server_config(&server_spiffe), authorizer)
            .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
            .await
            .expect("start quiet-watch listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let client = persistent_client(
        &pki,
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        &server_spiffe,
        &client_spiffe,
        scope,
        config(1, 0, 1),
    );
    let quiet_watch = client.open_watch(0).await.expect("open quiet watch");
    let shutdown_client = client.clone();
    let shutdown = tokio::spawn(async move { shutdown_client.shutdown().await });
    tokio::time::timeout(Duration::from_millis(250), async {
        loop {
            if client.capabilities().await == Err(SessionConsumerClientError::ShuttingDown) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown enters draining before caller cancellation");
    shutdown.abort();
    let _ = shutdown.await;

    tokio::time::timeout(Duration::from_millis(1_500), async {
        while client.diagnostics().await.watch_active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pool-owned forced shutdown releases the quiet watch task");
    let report = client.shutdown().await;
    assert_eq!(report.forced_watches, 1);
    assert_eq!(client.diagnostics().await.watch_active, 0);
    drop(quiet_watch);
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn shutting_down_one_derived_pool_does_not_rotate_its_live_sibling() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("sibling-shutdown-server");
    let client_spiffe = spiffe("sibling-shutdown-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let (handle, address) =
        SessionQuorumConsumerServer::new(service, pki.server_config(&server_spiffe), authorizer)
            .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
            .await
            .expect("start sibling-pool listener");
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(address) }));
    let reauthentication = SessionReauthenticationControl::new();
    let initial_generation = reauthentication.generation();
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(2))
    .with_reauthentication_control(reauthentication.clone());
    let first =
        PersistentSessionConsumerClient::try_from_stateless(stateless.clone(), config(1, 0, 1))
            .expect("first derived pool");
    let sibling = PersistentSessionConsumerClient::try_from_stateless(stateless, config(1, 0, 1))
        .expect("sibling derived pool");
    sibling
        .prewarm()
        .await
        .expect("prewarm sibling request lane");
    let sibling_watch = sibling.open_watch(0).await.expect("open sibling watch");

    first.shutdown().await;
    assert_eq!(reauthentication.generation(), initial_generation);
    assert_eq!(sibling.capabilities().await, Ok(transported_capabilities()));
    assert_eq!(sibling.diagnostics().await.watch_active, 1);

    drop(sibling_watch);
    sibling.shutdown().await;
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn consumer_listener_preserves_stateless_bounds_and_reaps_a_tls_blackhole() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("bounded-listener-server");
    let client_spiffe = spiffe("bounded-listener-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let occupied = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve an address");
    let occupied_address = occupied.local_addr().expect("reserved address");

    let error = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer.clone(),
    )
    .with_max_connections(Semaphore::MAX_PERMITS.saturating_add(1))
    .listen(occupied_address)
    .await
    .expect_err("a semaphore-unrepresentable listener ceiling is rejected before bind");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let error = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer.clone(),
    )
    .with_idle_timeout(Duration::ZERO)
    .listen(occupied_address)
    .await
    .expect_err("a zero pre-authentication timeout is rejected before bind");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    drop(occupied);

    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer.clone(),
    )
    .with_max_connections(1)
    .with_idle_timeout(Duration::from_millis(100))
    .with_operation_timeout(Duration::from_millis(100))
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start bounded listener");
    let mut blackhole = tokio::net::TcpStream::connect(address)
        .await
        .expect("open silent unauthenticated connection");
    let recovery_deadline = tokio::time::Instant::now() + Duration::from_millis(750);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        tokio::time::timeout_at(recovery_deadline, blackhole.read_u8())
            .await
            .expect("the TLS blackhole is reaped within the fixed recovery bound")
            .is_err(),
        "an unauthenticated blackhole must close without a server response"
    );

    // A malformed five-byte TLS header must be accepted and closed promptly.
    // This directly proves that the sole listener permit was returned before
    // the authenticated successor starts; merely racing another ClientHello
    // against the expiring blackhole makes the fixture scheduler-dependent on
    // slower 32-bit runners.
    let mut release_probe = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect post-blackhole permit probe");
    release_probe
        .write_all(&[0_u8; 5])
        .await
        .expect("write malformed TLS header");
    // The blackhole EOF is the recovery boundary. Give the independent
    // post-recovery accept/reject proof its own finite scheduler budget; tying
    // it to the nearly consumed outer deadline can leave a correct listener
    // with effectively no opportunity to poll its returned permit.
    let probe_deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    let mut discarded_probe_response = tokio::io::sink();
    tokio::time::timeout_at(
        probe_deadline,
        tokio::io::copy(&mut release_probe, &mut discarded_probe_response),
    )
    .await
    .expect("the released listener permit accepts and closes the bounded probe")
    .expect("drain the fixed TLS rejection");

    drop(blackhole);
    handle.abort_and_wait().await;

    // Keep the adversarial 100 ms setup bound above scoped to the blackhole
    // reaper. A legitimate authenticated successor is a separate proof: its
    // listener retains the fixed one-connection ceiling but gets the normal
    // finite setup budget. The proxy connects upstream first and deliberately
    // withholds the ClientHello for longer than the blackhole budget, sealing
    // that these two independent bounds cannot accidentally be coupled again.
    const AUTHENTICATED_SETUP_DELAY: Duration = Duration::from_millis(125);
    let (authenticated_handle, authenticated_upstream) =
        SessionQuorumConsumerServer::new(service, pki.server_config(&server_spiffe), authorizer)
            .with_max_connections(1)
            .with_operation_timeout(Duration::from_secs(1))
            .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
            .await
            .expect("start authenticated successor listener");
    let proxy_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind authenticated setup-delay proxy");
    let proxy_address = proxy_listener.local_addr().expect("proxy address");
    let proxy_task = tokio::spawn(async move {
        let (mut downstream, _) = proxy_listener.accept().await.expect("accept client");
        let mut upstream = tokio::net::TcpStream::connect(authenticated_upstream)
            .await
            .expect("connect successor listener before delaying ClientHello");
        tokio::time::sleep(AUTHENTICATED_SETUP_DELAY).await;
        let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
    });
    let resolver: RemoteAddrResolver = Arc::new(move || Box::pin(async move { Ok(proxy_address) }));
    let client = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(proxy_address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_operation_timeout(Duration::from_secs(1));
    let authenticated_deadline = tokio::time::Instant::now() + Duration::from_millis(750);
    assert_eq!(
        tokio::time::timeout_at(authenticated_deadline, client.capabilities())
            .await
            .expect("the separately bounded authenticated successor completes"),
        Ok(transported_capabilities())
    );

    proxy_task.abort();
    authenticated_handle.abort_and_wait().await;
}

#[tokio::test]
async fn persistent_setup_preserves_the_shorter_stateless_pre_request_budget() {
    let pki = TestPki::new();
    let server_spiffe = spiffe("setup-budget-server");
    let client_spiffe = spiffe("setup-budget-client");
    let (authorizer, scope) = authorizer_and_scope(&client_spiffe).await;
    let service = Arc::new(ControlledConsumer::default());
    let (handle, address) = SessionQuorumConsumerServer::new(
        service.clone(),
        pki.server_config(&server_spiffe),
        authorizer,
    )
    .listen("127.0.0.1:0".parse::<SocketAddr>().expect("listen address"))
    .await
    .expect("start consumer listener");
    let resolves = Arc::new(AtomicUsize::new(0));
    let resolver: RemoteAddrResolver = {
        let resolves = Arc::clone(&resolves);
        Arc::new(move || {
            let resolves = Arc::clone(&resolves);
            Box::pin(async move {
                resolves.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(75)).await;
                Ok(address)
            })
        })
    };
    let stateless = StatelessSessionConsumerClient::new_with_resolver(
        resolver,
        rustls_pki_types::ServerName::IpAddress(address.ip().into()),
        SpiffeId::new(&server_spiffe).expect("server SPIFFE"),
        scope,
        pki.client_config(&client_spiffe),
    )
    .with_pre_request_connection_timeout(Duration::from_millis(25))
    .with_operation_timeout(Duration::from_secs(1));
    let client = PersistentSessionConsumerClient::try_from_stateless(stateless, config(1, 0, 1))
        .expect("persistent client");
    let request = SessionConsumerRequest::new(
        scope,
        opc_session_store::SessionConsumerRequestId::from_bytes([91; 16]),
        SessionConsumerOperation::AcquireLease {
            key: SessionKey {
                tenant: TenantId::new("setup-budget").expect("test tenant"),
                nf_kind: NetworkFunctionKind::smf(),
                key_type: SessionKeyType::PduSession,
                stable_id: Bytes::from_static(b"opaque-setup-budget")
                    .try_into()
                    .expect("bounded stable ID"),
            },
            owner: opc_session_store::OwnerId::new("setup-budget-owner").expect("test owner"),
            ttl: Duration::from_secs(30),
        },
    );

    assert!(matches!(
        tokio::time::timeout(Duration::from_millis(500), client.execute(&request))
            .await
            .expect("the inherited setup budget is finite"),
        Err(PersistentSessionConsumerExecuteError::NotTransmitted {
            cause: SessionConsumerClientError::Unavailable,
        })
    ));
    assert!((1..=2).contains(&resolves.load(Ordering::SeqCst)));
    assert_eq!(service.calls.load(Ordering::SeqCst), 0);

    client.shutdown().await;
    handle.abort_and_wait().await;
}
