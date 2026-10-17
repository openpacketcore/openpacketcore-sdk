use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use opc_amf_lite::AmfConfig;
use opc_config_bus::{CommitWrite, EncryptingManagedDatastore, ManagedDatastore, StoredConfig};
use opc_config_bus_consensus::RaftManagedDatastore;
use opc_config_model::{RequestSource, TrustedPrincipal, WorkloadIdentity};
use opc_consensus::{ConsensusPeerError, ConsensusRpcFamily, ConsensusWireRequest};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, DurableReadinessState, EncryptedSessionPayload,
    EncryptingSessionBackend, Generation, OwnerId, SessionBackend, SessionKey, SessionKeyType,
    SessionLeaseManager, StableId, StateClass, StateType, StoredSessionRecord,
};
use opc_session_testkit::ConsensusTestCluster;
use opc_types::{ConfigVersion, NetworkFunctionKind, TenantId, TxId};

mod config_consensus_common;
use config_consensus_common::{cluster_transition_timeout, ConfigCluster};

const INVALID_INNER_PAYLOAD: &[u8] = b"not-a-consensus-command";
const SESSION_BACKEND_NAMESPACE: &str = "config-session-scope-isolation";

fn tenant() -> TenantId {
    TenantId::new("scope-isolation-tenant").expect("test tenant")
}

fn principal() -> TrustedPrincipal {
    TrustedPrincipal::new(
        WorkloadIdentity::Internal("scope-isolation-writer".to_owned()),
        tenant(),
    )
}

fn provider() -> Arc<MemoryKeyProvider> {
    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("scope-isolation-config-key").expect("config key ID"),
            KeyPurpose::Config,
            tenant(),
            Zeroizing::new([0x25; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("insert config key");
    provider
        .insert_active_key(
            KeyId::new("scope-isolation-session-key").expect("session key ID"),
            KeyPurpose::Session,
            tenant(),
            Zeroizing::new([0x52; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("insert session key");
    provider
}

fn config_record(
    tx_id: TxId,
    parent_tx_id: Option<TxId>,
    version: u64,
    hostname: &str,
) -> StoredConfig<AmfConfig> {
    let mut record = StoredConfig::new(
        tx_id,
        ConfigVersion::new(version),
        principal(),
        RequestSource::Internal,
        AmfConfig {
            hostname: hostname.to_owned(),
            ..AmfConfig::default()
        },
    );
    record.parent_tx_id = parent_tx_id;
    record
}

fn session_key(stable_id: &'static [u8]) -> SessionKey {
    SessionKey {
        tenant: tenant(),
        nf_kind: NetworkFunctionKind::from_static("amf"),
        key_type: SessionKeyType::PduSession,
        stable_id: StableId::new(stable_id.to_vec()).expect("test stable ID"),
    }
}

async fn append_session_record<B>(
    store: &B,
    key: SessionKey,
    owner: &str,
    payload: &'static [u8],
) -> StoredSessionRecord
where
    B: SessionBackend + SessionLeaseManager,
{
    let owner = OwnerId::new(owner).expect("test owner");
    let lease = store
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .expect("acquire session lease");
    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner,
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("scope-isolation-record"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(payload),
    };
    assert_eq!(
        CompareAndSetResult::Success,
        store
            .compare_and_set(CompareAndSet {
                key,
                lease,
                expected_generation: None,
                new_record: record.clone(),
            })
            .await
            .expect("append session record")
    );
    record
}

fn assert_config_head_unchanged(before: &StoredConfig<AmfConfig>, after: &StoredConfig<AmfConfig>) {
    assert_eq!(before.tx_id, after.tx_id);
    assert_eq!(before.parent_tx_id, after.parent_tx_id);
    assert_eq!(before.version, after.version);
    assert_eq!(before.committed_at, after.committed_at);
    assert_eq!(before.principal, after.principal);
    assert_eq!(before.source, after.source);
    assert_eq!(before.schema_digest, after.schema_digest);
    assert_eq!(before.plaintext_digest, after.plaintext_digest);
    assert_eq!(before.config, after.config);
    assert_eq!(before.encrypted_blob, after.encrypted_blob);
    assert_eq!(before.idempotency_key, after.idempotency_key);
    assert_eq!(before.apply_plan, after.apply_plan);
    assert_eq!(before.request_fingerprint, after.request_fingerprint);
    assert_eq!(before.request_id, after.request_id);
    assert_eq!(before.recovery_required, after.recovery_required);
    assert_eq!(before.confirmed_deadline, after.confirmed_deadline);
    assert_eq!(before.rollback_label, after.rollback_label);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn config_and_session_groups_are_scope_and_availability_isolated() {
    let temp = tempfile::tempdir().expect("config cluster tempdir");
    let mut config_cluster = ConfigCluster::start(temp.path()).await;
    let session_cluster = ConsensusTestCluster::start(3).await;
    let provider = provider();

    assert_ne!(
        config_cluster.identity(),
        session_cluster.consensus_identity(),
        "config and session groups must use distinct consensus identities"
    );

    let config_writer = EncryptingManagedDatastore::new(
        Arc::new(RaftManagedDatastore::<AmfConfig>::new(Arc::new(
            config_cluster.stores[0].clone(),
        ))),
        Arc::clone(&provider),
    );
    let config_reader = EncryptingManagedDatastore::new(
        Arc::new(RaftManagedDatastore::<AmfConfig>::new(Arc::new(
            config_cluster.stores[1].clone(),
        ))),
        Arc::clone(&provider),
    );
    let session_writer = EncryptingSessionBackend::new(
        Arc::new(session_cluster.store(0)),
        Arc::clone(&provider),
        SESSION_BACKEND_NAMESPACE,
    );
    let session_reader = EncryptingSessionBackend::new(
        Arc::new(session_cluster.store(1)),
        Arc::clone(&provider),
        SESSION_BACKEND_NAMESPACE,
    );

    let first_config_tx = TxId::new();
    config_writer
        .append_commit_write(CommitWrite::new(config_record(
            first_config_tx,
            None,
            1,
            "config-head-before-cross-route",
        )))
        .await
        .expect("append initial config head");
    let first_session_key = session_key(b"session-head-before-cross-route");
    let first_session_record = append_session_record(
        &session_writer,
        first_session_key.clone(),
        "session-writer-one",
        b"session-payload-before-cross-route",
    )
    .await;

    let config_head_before = config_reader
        .load_latest()
        .await
        .expect("read initial config head")
        .expect("initial config head");
    let session_head_before = session_reader
        .get(&first_session_key)
        .await
        .expect("read initial session head")
        .expect("initial session head");
    assert_eq!(first_session_record, session_head_before);

    // A successful quorum write can return before an uninvolved follower has
    // applied it. Synchronize the exact target handlers before capturing their
    // status so later equality cannot mistake legitimate catch-up for a side
    // effect of the rejected scope/member requests.
    tokio::join!(
        config_cluster.wait_ready(),
        session_cluster.wait_node_durable_ready(0),
    );

    let session_stores = (0..3)
        .map(|index| session_cluster.store(index))
        .collect::<Vec<_>>();
    let config_target = &config_cluster.stores[0];
    let session_target = &session_stores[0];
    let config_status_before = config_target.status();
    let session_status_before = session_target.status();
    let config_member_ids = config_cluster
        .stores
        .iter()
        .map(|store| store.status().node_id)
        .collect::<BTreeSet<_>>();
    let session_member_ids = session_stores
        .iter()
        .map(|store| store.status().node_id)
        .collect::<BTreeSet<_>>();

    // A valid target member sends an outer request carrying the other
    // consumer's scope and deliberately invalid inner bytes. ScopeMismatch,
    // rather than Protocol, proves rejection occurs before consumer decoding.
    let session_sender = session_target.status().node_id;
    let config_scoped_request = ConsensusWireRequest::try_new(
        config_cluster.identity(),
        session_sender,
        ConsensusRpcFamily::ForwardMutation,
        INVALID_INNER_PAYLOAD.to_vec(),
    )
    .expect("bounded config-scoped request");
    assert_eq!(
        Err(ConsensusPeerError::ScopeMismatch),
        session_target
            .rpc_handler()
            .handle(session_sender, config_scoped_request)
            .await
            .result
    );

    let config_sender = config_target.status().node_id;
    let session_scoped_request = ConsensusWireRequest::try_new(
        session_cluster.consensus_identity(),
        config_sender,
        ConsensusRpcFamily::ForwardMutation,
        INVALID_INNER_PAYLOAD.to_vec(),
    )
    .expect("bounded session-scoped request");
    assert_eq!(
        Err(ConsensusPeerError::ScopeMismatch),
        config_target
            .rpc_handler()
            .handle(config_sender, session_scoped_request)
            .await
            .result
    );

    // Use the target's correct scope while authenticating a real member of
    // the other group. Select by set difference so a future partial numeric
    // node-ID collision cannot accidentally turn this into a member request.
    // ScopeMismatch rather than Protocol proves membership rejection happens
    // before the deliberately invalid inner payload is decoded.
    let foreign_session_member = session_member_ids
        .difference(&config_member_ids)
        .next()
        .copied()
        .expect("session group has a member outside config membership");
    assert!(session_member_ids.contains(&foreign_session_member));
    assert!(!config_member_ids.contains(&foreign_session_member));
    let foreign_session_request = ConsensusWireRequest::try_new(
        config_cluster.identity(),
        foreign_session_member,
        ConsensusRpcFamily::ForwardMutation,
        INVALID_INNER_PAYLOAD.to_vec(),
    )
    .expect("bounded foreign-session-member request");
    assert_eq!(
        Err(ConsensusPeerError::ScopeMismatch),
        config_target
            .rpc_handler()
            .handle(foreign_session_member, foreign_session_request)
            .await
            .result
    );

    let foreign_config_member = config_member_ids
        .difference(&session_member_ids)
        .next()
        .copied()
        .expect("config group has a member outside session membership");
    assert!(config_member_ids.contains(&foreign_config_member));
    assert!(!session_member_ids.contains(&foreign_config_member));
    let foreign_config_request = ConsensusWireRequest::try_new(
        session_cluster.consensus_identity(),
        foreign_config_member,
        ConsensusRpcFamily::ForwardMutation,
        INVALID_INNER_PAYLOAD.to_vec(),
    )
    .expect("bounded foreign-config-member request");
    assert_eq!(
        Err(ConsensusPeerError::ScopeMismatch),
        session_target
            .rpc_handler()
            .handle(foreign_config_member, foreign_config_request)
            .await
            .result
    );

    assert_eq!(
        config_status_before,
        config_target.status(),
        "rejected scope/member requests must not change config Raft state"
    );
    assert_eq!(
        session_status_before,
        session_target.status(),
        "rejected scope/member requests must not change session Raft state"
    );

    let config_head_after = config_reader
        .load_latest()
        .await
        .expect("read config head after cross-route")
        .expect("config head after cross-route");
    assert_config_head_unchanged(&config_head_before, &config_head_after);
    assert_eq!(
        session_head_before,
        session_reader
            .get(&first_session_key)
            .await
            .expect("read session head after cross-route")
            .expect("session head after cross-route")
    );

    let second_config_tx = TxId::new();
    config_writer
        .append_commit_write(CommitWrite::new(config_record(
            second_config_tx,
            Some(first_config_tx),
            2,
            "config-head-after-cross-route",
        )))
        .await
        .expect("append config after cross-route");
    let config_after_write = config_reader
        .load_latest()
        .await
        .expect("read config after cross-route write")
        .expect("config after cross-route write");
    assert_eq!(second_config_tx, config_after_write.tx_id);
    assert_eq!(Some(first_config_tx), config_after_write.parent_tx_id);
    assert_eq!(ConfigVersion::new(2), config_after_write.version);
    assert_eq!(
        "config-head-after-cross-route",
        config_after_write.config.hostname
    );

    let second_session_key = session_key(b"session-head-after-cross-route");
    let second_session_record = append_session_record(
        &session_writer,
        second_session_key.clone(),
        "session-writer-two",
        b"session-payload-after-cross-route",
    )
    .await;
    assert_eq!(
        second_session_record,
        session_reader
            .get(&second_session_key)
            .await
            .expect("read session after cross-route write")
            .expect("session after cross-route write")
    );

    // Stop every config engine and release every adapter before reopening the
    // same durable paths. The co-resident session group must remain writable
    // and preserve both earlier records while config consensus is absent.
    drop(config_writer);
    drop(config_reader);
    config_cluster
        .shutdown()
        .await
        .expect("shutdown config cluster");
    drop(config_cluster);

    let third_session_key = session_key(b"session-while-config-stopped");
    let third_session_record = append_session_record(
        &session_writer,
        third_session_key.clone(),
        "session-writer-three",
        b"session-payload-while-config-stopped",
    )
    .await;
    assert_eq!(
        third_session_record,
        session_reader
            .get(&third_session_key)
            .await
            .expect("read session while config group is stopped")
            .expect("session written while config group is stopped")
    );
    assert_eq!(
        first_session_record,
        session_reader
            .get(&first_session_key)
            .await
            .expect("read first session while config group is stopped")
            .expect("first session while config group is stopped")
    );
    assert_eq!(
        second_session_record,
        session_reader
            .get(&second_session_key)
            .await
            .expect("read second session while config group is stopped")
            .expect("second session while config group is stopped")
    );

    let mut config_cluster = ConfigCluster::start(temp.path()).await;
    let config_writer = EncryptingManagedDatastore::new(
        Arc::new(RaftManagedDatastore::<AmfConfig>::new(Arc::new(
            config_cluster.stores[0].clone(),
        ))),
        Arc::clone(&provider),
    );
    let config_reader = EncryptingManagedDatastore::new(
        Arc::new(RaftManagedDatastore::<AmfConfig>::new(Arc::new(
            config_cluster.stores[1].clone(),
        ))),
        Arc::clone(&provider),
    );
    let config_after_restart = config_reader
        .load_latest()
        .await
        .expect("read config after full group restart")
        .expect("config head after full group restart");
    assert_config_head_unchanged(&config_after_write, &config_after_restart);

    // Taking every in-process session consensus path offline is a complete
    // quorum outage, not a process/engine shutdown. Each node must report the
    // same fail-closed readiness state while config consensus continues.
    for index in 0..session_stores.len() {
        session_cluster.set_node_online(index, false);
    }
    let readiness_reports = tokio::time::timeout(cluster_transition_timeout(), async {
        let (one, two, three) = tokio::join!(
            session_stores[0].probe_durable_readiness(),
            session_stores[1].probe_durable_readiness(),
            session_stores[2].probe_durable_readiness(),
        );
        [one, two, three]
    })
    .await
    .expect("session quorum-outage readiness checks are bounded");
    for report in readiness_reports {
        assert_eq!(DurableReadinessState::NoQuorum, report.state());
    }

    let third_config_tx = TxId::new();
    config_writer
        .append_commit_write(CommitWrite::new(config_record(
            third_config_tx,
            Some(second_config_tx),
            3,
            "config-head-while-session-quorum-down",
        )))
        .await
        .expect("append config while session quorum is down");
    let config_during_session_outage = config_reader
        .load_latest()
        .await
        .expect("read config while session quorum is down")
        .expect("config head while session quorum is down");
    assert_eq!(third_config_tx, config_during_session_outage.tx_id);
    assert_eq!(
        Some(second_config_tx),
        config_during_session_outage.parent_tx_id
    );
    assert_eq!(ConfigVersion::new(3), config_during_session_outage.version);
    assert_eq!(
        "config-head-while-session-quorum-down",
        config_during_session_outage.config.hostname
    );

    for index in 0..session_stores.len() {
        session_cluster.set_node_online(index, true);
    }
    tokio::time::timeout(cluster_transition_timeout(), async {
        tokio::join!(
            session_cluster.wait_node_durable_ready(0),
            session_cluster.wait_node_durable_ready(1),
            session_cluster.wait_node_durable_ready(2),
        );
    })
    .await
    .expect("session quorum heal is bounded");

    assert_eq!(
        first_session_record,
        session_reader
            .get(&first_session_key)
            .await
            .expect("read first session after quorum heal")
            .expect("first session after quorum heal")
    );
    assert_eq!(
        second_session_record,
        session_reader
            .get(&second_session_key)
            .await
            .expect("read second session after quorum heal")
            .expect("second session after quorum heal")
    );
    assert_eq!(
        third_session_record,
        session_reader
            .get(&third_session_key)
            .await
            .expect("read third session after quorum heal")
            .expect("third session after quorum heal")
    );

    let fourth_session_key = session_key(b"session-after-quorum-heal");
    let fourth_session_record = append_session_record(
        &session_writer,
        fourth_session_key.clone(),
        "session-writer-four",
        b"session-payload-after-quorum-heal",
    )
    .await;
    assert_eq!(
        fourth_session_record,
        session_reader
            .get(&fourth_session_key)
            .await
            .expect("read session written after quorum heal")
            .expect("session written after quorum heal")
    );
    let config_after_session_heal = config_reader
        .load_latest()
        .await
        .expect("read config after session quorum heal")
        .expect("config head after session quorum heal");
    assert_config_head_unchanged(&config_during_session_outage, &config_after_session_heal);

    drop(config_writer);
    drop(config_reader);
    config_cluster
        .shutdown()
        .await
        .expect("shutdown restarted config cluster");
}
