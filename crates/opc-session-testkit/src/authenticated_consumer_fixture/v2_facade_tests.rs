//! Protected V2 consumer facade evidence against three real authenticated
//! OpenRaft voters (#982).
//!
//! Every mutation and receipt read below crosses the production mTLS `/2`
//! lane into the real store-owned quorum service. The fixture decorator only
//! counts calls and, when armed, withholds one committed response.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use opc_key::{
    KeyError, KeyHandle, KeyId, KeyPurpose, MemoryKeyProvider, MemoryRemoteSealProvider, Zeroizing,
    AES_256_GCM_SIV_KEY_LEN,
};
use opc_session_net::{
    SessionConsumerFencedTransitionV2ReleaseError,
    SessionConsumerPreparedFencedTransitionStatusError, SessionConsumerRecoveredFencedTransition,
};
use opc_session_store::{
    EncryptedSessionPayload, FenceToken, FencedTransitionExecuteError, FencedTransitionLease,
    FencedTransitionMutation, FencedTransitionRequest, FencedTransitionRequestId,
    FencedTransitionStatus, FencedTransitionV2Status, Generation, OwnerId,
    PreparedCheckpointBudget, SessionKey, SessionKeyType, StateClass, StateType, StoreError,
    StoredSessionRecord, FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES,
};
use opc_types::{NetworkFunctionKind, TenantId};

use super::*;

const PAYLOAD: &[u8] = b"fixture-v2-facade-payload";

fn tenant() -> TenantId {
    TenantId::new("fixture-v2-facade").expect("fixture tenant")
}

fn scope() -> SessionConsumerTenantNfScope {
    SessionConsumerTenantNfScope::new(tenant(), NetworkFunctionKind::smf())
}

fn session_key(label: u64) -> SessionKey {
    SessionKey {
        tenant: tenant(),
        nf_kind: NetworkFunctionKind::smf(),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(format!("fixture-v2-facade-session-{label}").into_bytes())
            .try_into()
            .expect("fixture stable session ID"),
    }
}

fn owner() -> OwnerId {
    OwnerId::new("fixture-v2-facade-owner").expect("fixture owner")
}

fn request_id(ordinal: u64) -> FencedTransitionRequestId {
    let mut bytes = [0x5e_u8; 16];
    bytes[8..].copy_from_slice(&ordinal.to_be_bytes());
    FencedTransitionRequestId::from_bytes(bytes)
}

/// First acquire-and-create for one fresh key.
fn create(id: FencedTransitionRequestId, label: u64, payload: &[u8]) -> FencedTransitionRequest {
    let key = session_key(label);
    let lease = FencedTransitionLease::acquire(
        key.clone(),
        owner(),
        FenceToken::new(0),
        Duration::from_secs(30),
    )
    .expect("fixture acquire lease");
    FencedTransitionRequest::new(
        id,
        lease.clone(),
        FencedTransitionMutation::create(StoredSessionRecord {
            key,
            generation: Generation::new(1),
            owner: owner(),
            fence: lease.committed_fence().expect("fixture committed fence"),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("fixture-v2-facade"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(payload),
        }),
    )
    .expect("fixture create transition")
}

fn budget(deadline: tokio::time::Instant) -> PreparedCheckpointBudget {
    PreparedCheckpointBudget::new(deadline, Duration::from_millis(250))
        .expect("fixture immutable request budget")
}

fn soon() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(5)
}

struct CountingProvider {
    inner: MemoryKeyProvider,
    calls: AtomicUsize,
}

impl CountingProvider {
    fn new() -> Arc<Self> {
        let inner = MemoryKeyProvider::new();
        inner
            .insert_active_key(
                KeyId::new("fixture-v2-facade-active").expect("fixture key ID"),
                KeyPurpose::Session,
                tenant(),
                Zeroizing::new([0x6d; AES_256_GCM_SIV_KEY_LEN]),
            )
            .expect("install fixture local AEAD key");
        Arc::new(Self {
            inner,
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl KeyProvider for CountingProvider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_active_key(purpose, tenant).await
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_key_by_id(key_id).await
    }

    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.rotate_key(purpose, tenant).await
    }
}

fn recovered_v2(
    recovered: Option<SessionConsumerRecoveredFencedTransition>,
) -> opc_session_net::SessionConsumerRecoveredFencedTransitionV2Status {
    match recovered.expect("the recovery journal retains the caller ID") {
        SessionConsumerRecoveredFencedTransition::V2(recovered) => recovered,
        other => panic!("expected a retained V2 transition, got {other:?}"),
    }
}

#[tokio::test]
async fn fixture_v2_facade_commits_releases_and_readmits_one_caller_id() {
    let fixture = AuthenticatedPreparedFencedTransitionFixture::start([scope()])
        .await
        .expect("start authenticated three-voter fixture");
    let provider = CountingProvider::new();
    let facade = fixture
        .open_local_aead_v2(Arc::clone(&provider), "fixture-v2-commit")
        .await
        .expect("activate every real voter's /2 lane");
    let id = request_id(1);
    let request = create(id, 1, PAYLOAD);
    let mut prepared = facade
        .prepare_fenced_transition(request.clone(), budget(soon()))
        .await
        .expect("prepare in the linearized active epoch");
    assert_eq!(prepared.request_id(), id);
    assert_eq!(provider.calls(), 1, "create is sealed exactly once");
    assert_eq!(
        facade.retained_fenced_transitions().await.expect("count"),
        1
    );
    assert_eq!(
        fixture.diagnostics().fenced_transition_v2_calls(),
        0,
        "preparation never dispatches"
    );

    let outcome = prepared
        .execute_once()
        .await
        .expect("one real protected V2 transition commits");
    assert!(outcome.matches_request(&request));
    assert_eq!(fixture.diagnostics().fenced_transition_v2_calls(), 1);
    assert_eq!(
        fixture.diagnostics().fenced_transition_calls(),
        0,
        "no V1 transition binding is consumed"
    );

    let observed = facade
        .observe_fenced_transition(&session_key(1))
        .await
        .expect("observe the committed head through the facade");
    let record = observed.record().expect("committed record");
    assert_eq!(record.generation, Generation::new(1));
    assert_eq!(record.payload.as_bytes(), PAYLOAD);

    prepared
        .release_resolved()
        .await
        .expect("an exact committed outcome permits release");
    prepared
        .release_resolved()
        .await
        .expect("releasing twice is a no-op");
    assert_eq!(
        facade.retained_fenced_transitions().await.expect("count"),
        0
    );
    assert!(facade
        .recover_fenced_transition_status(id, budget(soon()))
        .await
        .expect("recovery lookup")
        .is_none());

    // A released caller ID is no longer bound: it may name a new transition
    // derived from the authoritative head.
    let renewal = FencedTransitionRequest::new(
        id,
        FencedTransitionLease::renew(outcome.lease().clone(), Duration::from_secs(30))
            .expect("fixture renewal"),
        FencedTransitionMutation::delete(Generation::new(1)),
    )
    .expect("fixture delete transition");
    let mut successor = facade
        .prepare_fenced_transition(renewal, budget(soon()))
        .await
        .expect("prepare a successor under the released ID");
    successor
        .execute_once()
        .await
        .expect("the successor commits");
    assert_eq!(provider.calls(), 2, "delete performs no provider work");
    assert!(facade
        .observe_fenced_transition(&session_key(1))
        .await
        .expect("observe the deleted head")
        .record()
        .is_none());
    drop(successor);
    drop(prepared);
    drop(facade);
    fixture.shutdown().await.expect("shut down fixture");
}

#[tokio::test]
async fn fixture_v2_facade_recovers_a_real_lost_response_by_caller_id_without_replay() {
    let mut fixture = AuthenticatedPreparedFencedTransitionFixture::start([scope()])
        .await
        .expect("start authenticated three-voter fixture");
    let provider = CountingProvider::new();
    let id = request_id(2);
    let facade = fixture
        .open_local_aead_v2(Arc::clone(&provider), "fixture-v2-recovery")
        .await
        .expect("open protected V2 facade");
    let mut prepared = facade
        .prepare_fenced_transition(create(id, 2, PAYLOAD), budget(soon()))
        .await
        .expect("prepare");
    fixture.lose_next_fenced_transition_v2_response();
    assert_eq!(
        prepared.execute_once().await,
        Err(FencedTransitionExecuteError::OutcomeUnknown { request_id: id }),
        "the real service commits, then only its response is withheld"
    );
    let after_ambiguous = fixture.diagnostics();
    assert_eq!(after_ambiguous.fenced_transition_v2_calls(), 1);
    assert_eq!(
        prepared.release_resolved().await,
        Err(SessionConsumerFencedTransitionV2ReleaseError::NotResolved),
        "an unknown outcome is never released"
    );
    drop(prepared);
    drop(facade);

    fixture
        .restart_listeners()
        .await
        .expect("restart only the authenticated frontends");
    // A new process retains only the caller-stable ID: neither the plaintext
    // body nor the original provider instance survives.
    let restarted_provider = CountingProvider::new();
    let reopened = fixture
        .open_local_aead_v2(Arc::clone(&restarted_provider), "fixture-v2-recovery")
        .await
        .expect("reopen the same recovery journal");
    let deadline = soon();
    let mut recovered = recovered_v2(
        reopened
            .recover_fenced_transition_status(id, budget(deadline))
            .await
            .expect("recover by caller-stable ID"),
    );
    assert_eq!(recovered.request_id(), id);
    let receipt = recovered
        .status_until_terminal(deadline)
        .await
        .expect("receipt-only recovery converges");
    assert!(
        matches!(receipt, FencedTransitionV2Status::Recorded(ref result) if result.is_ok()),
        "the receipt is the real committed transition"
    );
    let after_recovery = fixture.diagnostics();
    assert_eq!(
        after_recovery.fenced_transition_v2_calls(),
        after_ambiguous.fenced_transition_v2_calls(),
        "recovery never replays the mutation"
    );
    assert!(after_recovery.fenced_transition_v2_status_calls() > 0);
    assert_eq!(
        restarted_provider.calls(),
        0,
        "recovery never reseals or unseals"
    );
    assert_eq!(
        reopened
            .prepare_fenced_transition(create(id, 3, PAYLOAD), budget(soon()))
            .await
            .expect_err("a retained caller ID cannot start a second lineage"),
        StoreError::FencedTransitionRequestConflict
    );
    assert_eq!(
        restarted_provider.calls(),
        0,
        "the conflict precedes provider work"
    );
    recovered
        .release_resolved()
        .await
        .expect("a terminal receipt permits release");
    assert_eq!(
        reopened.retained_fenced_transitions().await.expect("count"),
        0
    );
    drop(recovered);
    drop(reopened);
    fixture.shutdown().await.expect("shut down fixture");
}

#[tokio::test]
async fn fixture_v2_facade_crash_after_prepare_before_send_restarts_status_only() {
    let fixture = AuthenticatedPreparedFencedTransitionFixture::start([scope()])
        .await
        .expect("start authenticated three-voter fixture");
    let provider = CountingProvider::new();
    let id = request_id(4);
    let facade = fixture
        .open_local_aead_v2(Arc::clone(&provider), "fixture-v2-pre-send")
        .await
        .expect("open protected V2 facade");
    let prepared = facade
        .prepare_fenced_transition(create(id, 4, PAYLOAD), budget(soon()))
        .await
        .expect("prepare, then lose the process before dispatch");
    drop(prepared);
    drop(facade);
    let before = fixture.diagnostics();
    assert_eq!(before.fenced_transition_v2_calls(), 0);

    let reopened = fixture
        .open_local_aead_v2(Arc::clone(&provider), "fixture-v2-pre-send")
        .await
        .expect("a fresh process reopens the recovery journal");
    let status_deadline = tokio::time::Instant::now() + Duration::from_millis(800);
    let mut recovered = recovered_v2(
        reopened
            .recover_fenced_transition_status(id, budget(status_deadline))
            .await
            .expect("recover by caller-stable ID"),
    );
    assert_eq!(
        recovered.status_until_terminal(status_deadline).await,
        Err(SessionConsumerPreparedFencedTransitionStatusError::Deadline),
        "NotFound in the active epoch is non-exclusionary, so status never concludes"
    );
    assert_eq!(
        recovered.release_resolved().await,
        Err(SessionConsumerFencedTransitionV2ReleaseError::NotResolved),
        "a possibly pending first transition keeps its row"
    );
    assert_eq!(
        reopened
            .prepare_fenced_transition(create(id, 5, PAYLOAD), budget(soon()))
            .await
            .expect_err("the restarted consumer cannot start a second lineage"),
        StoreError::FencedTransitionRequestConflict
    );
    let after = fixture.diagnostics();
    assert_eq!(
        after.fenced_transition_v2_calls(),
        0,
        "restart performs no physical mutation for a pre-send row"
    );
    assert!(after.fenced_transition_v2_status_calls() > before.fenced_transition_v2_status_calls());
    let report = reopened
        .reclaim_resolved_fenced_transitions(16, budget(soon()))
        .await
        .expect("bounded reclamation sweep");
    assert_eq!(report.examined(), 1);
    assert_eq!(report.retained(), 1, "a NotFound row is never reclaimed");
    assert_eq!(report.reclaimed(), 0);
    assert_eq!(
        reopened.retained_fenced_transitions().await.expect("count"),
        1
    );
    drop(recovered);
    drop(reopened);
    fixture.shutdown().await.expect("shut down fixture");
}

#[tokio::test]
async fn fixture_v2_facade_upgrade_keeps_retained_v1_transitions_recoverable() {
    let fixture = AuthenticatedPreparedFencedTransitionFixture::start([scope()])
        .await
        .expect("start authenticated three-voter fixture");
    let provider = CountingProvider::new();
    let legacy_id = request_id(10);
    {
        let v1 = fixture
            .open_local_aead(Arc::clone(&provider), "fixture-v2-upgrade")
            .await
            .expect("open the pre-upgrade V1 facade");
        let mut prepared = v1
            .prepare_fenced_transition(create(legacy_id, 10, PAYLOAD), budget(soon()))
            .await
            .expect("prepare one retained V1 transition");
        prepared.execute_once().await.expect("commit it through V1");
    }
    assert_eq!(fixture.diagnostics().fenced_transition_calls(), 1);

    let upgraded = fixture
        .open_local_aead_v2_with_legacy_v1(Arc::clone(&provider), "fixture-v2-upgrade")
        .await
        .expect("compose V1 recovery under the V2 facade");
    let deadline = soon();
    let mut legacy = match upgraded
        .recover_fenced_transition_status(legacy_id, budget(deadline))
        .await
        .expect("unified recovery")
        .expect("the retained V1 row is found")
    {
        SessionConsumerRecoveredFencedTransition::LegacyV1(legacy) => legacy,
        other => panic!("expected the retained V1 transition, got {other:?}"),
    };
    assert!(matches!(
        legacy
            .status_until_terminal(deadline)
            .await
            .expect("exact V1 receipt"),
        FencedTransitionStatus::Recorded(result) if result.is_ok()
    ));
    let calls = provider.calls();
    assert_eq!(
        upgraded
            .prepare_fenced_transition(create(legacy_id, 11, PAYLOAD), budget(soon()))
            .await
            .expect_err("a retained V1 caller ID cannot start a V2 lineage"),
        StoreError::FencedTransitionRequestConflict
    );
    assert_eq!(
        provider.calls(),
        calls,
        "the conflict precedes provider work"
    );

    let v2_id = request_id(12);
    let mut prepared = upgraded
        .prepare_fenced_transition(create(v2_id, 12, PAYLOAD), budget(soon()))
        .await
        .expect("new transitions use V2");
    prepared.execute_once().await.expect("commit through V2");
    let diagnostics = fixture.diagnostics();
    assert_eq!(
        diagnostics.fenced_transition_calls(),
        1,
        "no new V1 binding"
    );
    assert_eq!(diagnostics.fenced_transition_v2_calls(), 1);
    assert!(matches!(
        upgraded
            .recover_fenced_transition_status(v2_id, budget(soon()))
            .await
            .expect("unified recovery of the V2 row"),
        Some(SessionConsumerRecoveredFencedTransition::V2(_))
    ));
    drop(prepared);
    drop(legacy);
    drop(upgraded);
    fixture.shutdown().await.expect("shut down fixture");
}

#[tokio::test]
async fn fixture_v2_facade_remote_sealing_commits_through_real_voters() {
    let fixture = AuthenticatedPreparedFencedTransitionFixture::start([scope()])
        .await
        .expect("start authenticated three-voter fixture");
    let provider = Arc::new(MemoryRemoteSealProvider::new(
        KeyId::new("fixture-v2-facade-remote").expect("fixture key ID"),
        KeyPurpose::Session,
        tenant(),
        Zeroizing::new([0x6e; AES_256_GCM_SIV_KEY_LEN]),
    ));
    let activated =
        SessionConsumerPreparedFencedTransitionV2Backend::persistent_exact_voter_prewarm_roster(
            fixture.persistent_clients().expect("fixture clients"),
        )
        .await
        .expect("activate every real voter's /2 lane");
    let facade = SessionConsumerPreparedFencedTransitionV2Backend::persistent_remote_sealing(
        activated,
        Arc::clone(&provider),
        "fixture-v2-remote",
        fixture.open_recovery_journal().expect("recovery journal"),
    )
    .expect("compose the remote-seal V2 facade");
    let mut prepared = facade
        .prepare_fenced_transition(create(request_id(20), 20, PAYLOAD), budget(soon()))
        .await
        .expect("remote-seal preparation");
    prepared
        .execute_once()
        .await
        .expect("one remote-sealed V2 transition commits");
    let observed = facade
        .observe_fenced_transition(&session_key(20))
        .await
        .expect("observe through the remote-seal facade");
    assert_eq!(
        observed
            .record()
            .expect("committed record")
            .payload
            .as_bytes(),
        PAYLOAD
    );
    assert_eq!(fixture.diagnostics().fenced_transition_v2_calls(), 1);
    drop(prepared);
    drop(facade);
    fixture.shutdown().await.expect("shut down fixture");
}

#[tokio::test]
async fn fixture_v2_facade_reclaim_sweep_retains_recorded_and_unresolved_rows() {
    let fixture = AuthenticatedPreparedFencedTransitionFixture::start([scope()])
        .await
        .expect("start authenticated three-voter fixture");
    let provider = CountingProvider::new();
    let facade = fixture
        .open_local_aead_v2(Arc::clone(&provider), "fixture-v2-sweep")
        .await
        .expect("open protected V2 facade");
    let mut committed = facade
        .prepare_fenced_transition(create(request_id(30), 30, PAYLOAD), budget(soon()))
        .await
        .expect("prepare the committed row");
    committed.execute_once().await.expect("commit it");
    let pending = facade
        .prepare_fenced_transition(create(request_id(31), 31, PAYLOAD), budget(soon()))
        .await
        .expect("prepare a row that is never dispatched");
    assert!(matches!(
        facade
            .reclaim_resolved_fenced_transitions(0, budget(soon()))
            .await,
        Err(StoreError::InvalidKey(_))
    ));
    let mutations = fixture.diagnostics().fenced_transition_v2_calls();
    let report = facade
        .reclaim_resolved_fenced_transitions(16, budget(soon()))
        .await
        .expect("bounded sweep");
    assert_eq!(report.examined(), 2);
    assert_eq!(
        report.retained(),
        2,
        "Recorded and NotFound rows are retained"
    );
    assert_eq!(report.reclaimed(), 0);
    assert!(!report.interrupted());
    assert_eq!(
        facade.retained_fenced_transitions().await.expect("count"),
        2
    );
    assert_eq!(
        fixture.diagnostics().fenced_transition_v2_calls(),
        mutations,
        "the sweep never dispatches a mutation"
    );
    committed
        .release_resolved()
        .await
        .expect("the committed row is released by its caller");
    let report = facade
        .reclaim_resolved_fenced_transitions(16, budget(soon()))
        .await
        .expect("a completed pass restarts from the beginning");
    assert_eq!(report.examined(), 1);
    assert_eq!(report.retained(), 1);
    assert_eq!(
        facade.retained_fenced_transitions().await.expect("count"),
        1
    );
    drop(pending);
    drop(committed);
    drop(facade);
    fixture.shutdown().await.expect("shut down fixture");
}

/// Release-profile qualification: more committed-and-released protected
/// transitions than one #701 V1 journal can ever hold. The recovery journal
/// stays at one live row throughout, so the V1 absorbing bound no longer
/// limits one consumer's lifetime.
#[tokio::test]
async fn fixture_v2_facade_keeps_the_linearized_history_read_off_the_preparation_path() {
    let fixture = AuthenticatedPreparedFencedTransitionFixture::start([scope()])
        .await
        .expect("start authenticated three-voter fixture");
    let provider = CountingProvider::new();
    let facade = fixture
        .open_local_aead_v2(Arc::clone(&provider), "fixture-v2-history-cache")
        .await
        .expect("activate every real voter's /2 lane");
    let activated = fixture.diagnostics();
    assert_eq!(
        activated.fenced_transition_v2_history_state_calls(),
        1,
        "activation seeds the active-epoch cache with one linearized read"
    );
    for ordinal in 0..4 {
        let id = request_id(0x4000 + ordinal);
        let request = create(id, 0x4000 + ordinal, PAYLOAD);
        let mut prepared = facade
            .prepare_fenced_transition(request.clone(), budget(soon()))
            .await
            .expect("prepare in the cached active epoch");
        let outcome = prepared
            .execute_once()
            .await
            .expect("the cached active epoch binds on a real voter");
        assert!(outcome.matches_request(&request));
        prepared
            .release_resolved()
            .await
            .expect("release the committed row");
    }
    let transitions = fixture.diagnostics();
    assert_eq!(transitions.fenced_transition_v2_calls(), 4);
    assert_eq!(
        transitions.fenced_transition_v2_history_state_calls(),
        activated.fenced_transition_v2_history_state_calls(),
        "no transition pays a consensus-backed history read"
    );
    facade
        .reclaim_resolved_fenced_transitions(16, budget(soon()))
        .await
        .expect("bounded sweep");
    assert_eq!(
        fixture
            .diagnostics()
            .fenced_transition_v2_history_state_calls(),
        activated.fenced_transition_v2_history_state_calls() + 1,
        "the maintenance sweep refreshes the cache with a linearized read"
    );
    drop(facade);
    fixture.shutdown().await.expect("shut down fixture");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "release qualification: 4,097+ real three-voter protected V2 transitions"]
async fn fixture_v2_facade_sustains_more_transitions_than_one_v1_journal_holds() {
    let transitions = FENCED_TRANSITION_V2_RECOVERY_JOURNAL_MAX_ENTRIES as u64 + 64;
    let fixture = AuthenticatedPreparedFencedTransitionFixture::start_fixed_durable([scope()])
        .await
        .expect("start durable authenticated three-voter fixture");
    let provider = CountingProvider::new();
    let facade = fixture
        .open_local_aead_v2(Arc::clone(&provider), "fixture-v2-sustained")
        .await
        .expect("open protected V2 facade");
    let started = std::time::Instant::now();
    let mut peak = 0_usize;
    let mut resolved_by_receipt = 0_u64;
    for ordinal in 1..=transitions {
        let request = create(request_id(ordinal), ordinal, PAYLOAD);
        let mut prepared = facade
            .prepare_fenced_transition(request.clone(), budget(soon()))
            .await
            .expect("prepare");
        match prepared.execute_once().await {
            Ok(outcome) => {
                assert!(outcome.matches_request(&request));
                peak = peak.max(facade.retained_fenced_transitions().await.expect("count"));
                prepared.release_resolved().await.expect("release");
            }
            // A durable commit that outlives one physical attempt is a
            // possible send. The handle's immutable budget may already be
            // spent, so a fresh receipt-only handle resolves the same caller
            // ID by exact status, never by a second mutation.
            Err(FencedTransitionExecuteError::OutcomeUnknown { request_id }) => {
                assert_eq!(request_id, prepared.request_id());
                resolved_by_receipt += 1;
                let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
                let mut recovered = recovered_v2(
                    facade
                        .recover_fenced_transition_status(request_id, budget(deadline))
                        .await
                        .expect("recover the ambiguous transition by caller ID"),
                );
                match recovered.status_until_terminal(deadline).await {
                    Ok(FencedTransitionV2Status::Recorded(result)) => {
                        let outcome = (*result).expect("the ambiguous transition committed");
                        assert!(outcome.matches_request(&request));
                    }
                    other => panic!("an ambiguous commit must resolve by receipt: {other:?}"),
                }
                peak = peak.max(facade.retained_fenced_transitions().await.expect("count"));
                recovered.release_resolved().await.expect("release");
            }
            Err(error) => panic!("unexpected protected V2 execution result: {error:?}"),
        }
    }
    let diagnostics = fixture.diagnostics();
    assert_eq!(
        diagnostics.fenced_transition_v2_calls() as u64,
        transitions,
        "every transition dispatched exactly once"
    );
    assert_eq!(diagnostics.fenced_transition_calls(), 0);
    assert_eq!(
        diagnostics.fenced_transition_v2_history_state_calls(),
        1,
        "the activation read serves every preparation"
    );
    assert_eq!(peak, 1, "retention is bounded by in-flight transitions");
    assert_eq!(
        facade.retained_fenced_transitions().await.expect("count"),
        0
    );
    eprintln!(
        "protected V2 facade sustained {transitions} committed transitions in {:?} \
         (peak retained rows {peak}, resolved by receipt {resolved_by_receipt})",
        started.elapsed()
    );
    drop(facade);
    fixture.shutdown().await.expect("shut down fixture");
}
