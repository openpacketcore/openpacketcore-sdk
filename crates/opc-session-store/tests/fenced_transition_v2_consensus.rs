//! Public V2 consensus-boundary coverage for SDK-702.
//!
//! The fixture is intentionally a `LabSingleton`, not a fake backend: each
//! operation still goes through Openraft proposal, durable SQLite apply, and
//! a consensus read barrier.  HA/membership and maintenance qualifications
//! require the internal operator-recovery and topology fixtures and are
//! recorded in `docs/sdk-702-nonabsorbing-fenced-history-evidence.md`.

use std::{collections::BTreeMap, path::Path, time::Duration};

use bytes::Bytes;
use opc_consensus::{
    derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_session_store::{
    fenced_transition_v2_profile_digest, ConsensusSessionStore, EncryptedSessionPayload,
    FenceToken, FencedTransitionLease, FencedTransitionMutation, FencedTransitionMutationResult,
    FencedTransitionV2CallerNonce, FencedTransitionV2Capability, FencedTransitionV2HistoryEpoch,
    FencedTransitionV2Request, FencedTransitionV2Status, Generation, OwnerId,
    QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaTlsIdentity, SessionBackend, SessionKey, SessionKeyType,
    SqliteSessionBackend, StateClass, StateType, StoreError, StoredSessionRecord,
    ValidatedQuorumTopology,
};
use opc_types::{NetworkFunctionKind, TenantId};

const OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const FIXED_V2_PROFILE_DIGEST: [u8; 32] = [
    0x8a, 0x0b, 0x70, 0xb5, 0x46, 0x54, 0xc7, 0x25, 0x0c, 0xf5, 0x46, 0x9d, 0xb6, 0xe1, 0xe5, 0x45,
    0xf3, 0x5e, 0x38, 0xe9, 0x77, 0x8d, 0x5f, 0x50, 0x0f, 0xea, 0x67, 0x06, 0x96, 0xc4, 0xbd, 0xc3,
];

fn replica_id() -> ReplicaId {
    ReplicaId::new("sdk-702-lab-voter").expect("replica ID")
}

fn member() -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        replica_id(),
        ReplicaEndpoint::new("sdk-702-lab-voter.invalid", 7443).expect("endpoint"),
        ReplicaTlsIdentity::new("spiffe://test/session/sdk-702-lab-voter").expect("TLS identity"),
        ReplicaFailureDomain::new("sdk-702-lab-zone").expect("failure domain"),
        ReplicaBackingIdentity::new("sdk-702-lab-disk").expect("backing identity"),
    )
}

fn topology() -> ValidatedQuorumTopology {
    let member = member();
    let members = vec![member.clone()];
    let cluster_id = ConsensusClusterId::new("sdk-702-v2-consensus-test").expect("cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(1).expect("configuration epoch");
    let fingerprints = members
        .iter()
        .map(QuorumReplicaDescriptor::configuration_fingerprint)
        .collect::<Vec<_>>();
    let identity = ConsensusIdentity::new(
        cluster_id,
        derive_configuration_id(cluster_id, epoch, &fingerprints),
        epoch,
    );
    ValidatedQuorumTopology::try_new_consensus_lab_singleton(replica_id(), members, identity)
        .expect("lab singleton topology")
}

async fn store(root: &Path) -> ConsensusSessionStore {
    let store = open_store(root).await;
    store
        .initialize_cluster()
        .await
        .expect("form one-voter consensus cluster");
    store
}

async fn open_store(root: &Path) -> ConsensusSessionStore {
    ConsensusSessionStore::open_with_operation_timeout(
        topology(),
        SqliteSessionBackend::open(root.join("store.sqlite")).expect("SQLite backend"),
        root.join("snapshots"),
        BTreeMap::new(),
        OPERATION_TIMEOUT,
    )
    .await
    .expect("open one-voter consensus store")
}

fn key(label: &[u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("sdk-702-v2").expect("tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(label).try_into().expect("stable ID"),
    }
}

fn owner() -> OwnerId {
    OwnerId::new("sdk-702-v2-owner").expect("owner")
}

fn sealing_provider() -> MemoryKeyProvider {
    let provider = MemoryKeyProvider::new();
    provider
        .insert_active_key(
            KeyId::new("sdk-702-v2-consensus-key").expect("key ID"),
            KeyPurpose::Session,
            TenantId::new("sdk-702-v2").expect("tenant"),
            Zeroizing::new([0x71; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("active session key");
    provider
}

fn record(
    key: SessionKey,
    owner: OwnerId,
    fence: FenceToken,
    payload: &'static [u8],
) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(1),
        owner,
        fence,
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("sdk-702-v2"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(Bytes::from_static(payload)),
    }
}

async fn sealed_record(
    key: SessionKey,
    owner: OwnerId,
    fence: FenceToken,
    payload: &'static [u8],
    provider: &MemoryKeyProvider,
) -> StoredSessionRecord {
    let mut record = record(key, owner, fence, payload);
    record.payload = EncryptedSessionPayload::encrypt(provider, &record, "sdk-702-v2-consensus")
        .await
        .expect("seal test transition payload");
    record
}

fn changed_body(request: &FencedTransitionV2Request) -> FencedTransitionV2Request {
    let mut encoded = serde_json::to_value(request).expect("serialize retained V2 request");
    let record = encoded
        .get_mut("mutation")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|mutation| mutation.get_mut("create"))
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|create| create.get_mut("record"))
        .and_then(serde_json::Value::as_object_mut)
        .expect("V2 create request record");
    record.insert(
        "state_type".to_owned(),
        serde_json::Value::String("sdk-702-v2-altered".to_owned()),
    );
    serde_json::from_value(encoded).expect("deserialize altered V2 request")
}

#[tokio::test]
async fn v2_first_transition_activates_through_consensus_and_replays_exactly() {
    let directory = tempfile::tempdir().expect("temporary consensus directory");
    let store = store(directory.path()).await;
    let provider = sealing_provider();
    assert_eq!(
        fenced_transition_v2_profile_digest(),
        FIXED_V2_PROFILE_DIGEST
    );
    assert_eq!(
        store
            .fenced_transition_v2_capability()
            .await
            .expect("V2 unanimous singleton capability"),
        Some(FencedTransitionV2Capability::V2)
    );
    assert!(matches!(
        store
            .recover_prepared_fenced_transition(
                opc_session_store::FencedTransitionRequestId::from_bytes([0xE2; 16]),
            )
            .await,
        Err(StoreError::CapabilityNotSupported(reason)) if reason == "atomic_fenced_transition_v2"
    ));

    let key = key(b"first-v2-transition");
    let owner = owner();
    let observation = store
        .observe_fenced_transition(&key)
        .await
        .expect("consensus fence observation");
    assert_eq!(observation.current_fence(), FenceToken::new(0));
    let lease = FencedTransitionLease::acquire(
        key.clone(),
        owner.clone(),
        observation.current_fence(),
        Duration::from_secs(60),
    )
    .expect("valid acquire");
    let mutation = FencedTransitionMutation::create(
        sealed_record(
            key,
            owner,
            FenceToken::new(1),
            b"first-v2-payload",
            &provider,
        )
        .await,
    );
    let request = FencedTransitionV2Request::new(
        FencedTransitionV2HistoryEpoch::new(1).expect("nonzero epoch"),
        FencedTransitionV2CallerNonce::from_bytes([0x71; 16]),
        lease,
        mutation,
    )
    .expect("self-authenticating V2 request");

    let first = store
        .fenced_transition_v2(request.clone())
        .await
        .expect("first V2 consensus apply");
    assert!(matches!(
        first.mutation(),
        FencedTransitionMutationResult::Created
    ));
    let replay = store
        .fenced_transition_v2(request.clone())
        .await
        .expect("exact V2 replay through consensus");
    assert_eq!(replay, first, "replay must not apply a second effect");
    assert!(matches!(
        store
            .fenced_transition_v2_status(&request)
            .await
            .expect("V2 status through read barrier"),
        FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(first)
    ));

    let history = store
        .fenced_transition_v2_history_state()
        .await
        .expect("V2 history state through read barrier");
    assert_eq!(
        history.active_epoch(),
        Some(FencedTransitionV2HistoryEpoch::new(1).expect("epoch"))
    );
    assert_eq!(history.bound_entries(), 1);
}

#[tokio::test]
async fn v2_durable_restart_preserves_exact_replay_and_changed_body_conflict() {
    let directory = tempfile::tempdir().expect("temporary consensus directory");
    let provider = sealing_provider();
    let key = key(b"durable-v2-restart");
    let owner = owner();
    let initial = store(directory.path()).await;
    let observation = initial
        .observe_fenced_transition(&key)
        .await
        .expect("consensus fence observation before restart");
    let lease = FencedTransitionLease::acquire(
        key.clone(),
        owner.clone(),
        observation.current_fence(),
        Duration::from_secs(60),
    )
    .expect("valid acquire");
    let expected_record = sealed_record(
        key.clone(),
        owner,
        FenceToken::new(1),
        b"durable-v2-restart-payload",
        &provider,
    )
    .await;
    let request = FencedTransitionV2Request::new(
        FencedTransitionV2HistoryEpoch::new(1).expect("epoch"),
        FencedTransitionV2CallerNonce::from_bytes([0x73; 16]),
        lease,
        FencedTransitionMutation::create(expected_record.clone()),
    )
    .expect("self-authenticating V2 request");
    let committed = initial
        .fenced_transition_v2(request.clone())
        .await
        .expect("commit V2 transition before restart");
    drop(initial);

    let restarted = store(directory.path()).await;
    assert_eq!(
        restarted
            .get(&key)
            .await
            .expect("read retained V2 record after restart"),
        Some(expected_record)
    );
    assert_eq!(
        restarted
            .fenced_transition_v2(request.clone())
            .await
            .expect("exact V2 replay after restart"),
        committed,
        "restart must retain the exact outcome without another mutation"
    );
    let altered = changed_body(&request);
    assert_eq!(
        restarted
            .fenced_transition_v2_status(&altered)
            .await
            .expect("changed-body V2 status after restart"),
        FencedTransitionV2Status::RequestConflict
    );
    assert_eq!(
        restarted.fenced_transition_v2(altered).await,
        Err(StoreError::FencedTransitionRequestConflict),
        "changed body under a retained full ID cannot execute after restart"
    );
}

#[test]
fn v2_changed_body_under_retained_full_id_conflicts_before_any_history_lookup() {
    let epoch = FencedTransitionV2HistoryEpoch::new(7).expect("nonzero epoch");
    let nonce = FencedTransitionV2CallerNonce::from_bytes([0x72; 16]);
    let key = key(b"commitment-before-floor");
    let owner = owner();
    let lease = FencedTransitionLease::acquire(
        key.clone(),
        owner.clone(),
        FenceToken::new(0),
        Duration::from_secs(60),
    )
    .expect("lease");
    let original = FencedTransitionV2Request::new(
        epoch,
        nonce,
        lease.clone(),
        FencedTransitionMutation::create(record(
            key.clone(),
            owner.clone(),
            FenceToken::new(1),
            b"original",
        )),
    )
    .expect("original request");
    let substituted = FencedTransitionV2Request::from_parts(
        original.request_id(),
        lease,
        FencedTransitionMutation::create(record(key, owner, FenceToken::new(1), b"substituted")),
    );
    assert_eq!(
        substituted,
        Err(StoreError::FencedTransitionRequestConflict)
    );
}
