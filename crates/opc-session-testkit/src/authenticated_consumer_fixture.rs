//! Production-shaped authenticated consumer fixture for downstream SDK tests.
//!
//! The fixture owns its OpenRaft voters, mTLS listeners, persistent clients,
//! and prepared-request journal. It offers either the opaque
//! [`SessionConsumerPreparedFencedTransitionBackend`] or a paired, ordinary
//! durable consumer view that shares its exact authority; neither route
//! exposes a physical client, prepared token, or activated roster.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use opc_identity::{
    build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle, TrustBundleSet, TrustDomain,
};
use opc_key::KeyProvider;
use opc_session_net::{
    PersistentSessionConsumerClient, PersistentSessionConsumerConfig, SessionConsumerAuthorizer,
    SessionConsumerLeaseMutationError, SessionConsumerMutationError,
    SessionConsumerPreparedFencedTransitionBackend,
    SessionConsumerPreparedFencedTransitionBackendError, SessionQuorumConsumerServer,
    SessionQuorumConsumerServerHandle, StatelessSessionConsumerClient,
};
use opc_session_store::{
    BackendCapabilities, CompareAndSet, CompareAndSetResult, EncryptingSessionBackend,
    FencedTransitionExecuteError, FencedTransitionOutcome, FencedTransitionRequest, LeaseError,
    LeaseGuard, OwnerId, PreparedCheckpointBudget, PreparedFencedTransitionJournal,
    PreparedFencedTransitionJournalKey, RecordExpiryPreflight, RestoreScanCursorProfile,
    RestoreScanPage, RestoreScanRequest, SessionBackend, SessionConsumerAuthorization,
    SessionConsumerAuthorizationGrant, SessionConsumerAuthorizationGrantError,
    SessionConsumerChange, SessionConsumerOperation, SessionConsumerRejection,
    SessionConsumerRequest, SessionConsumerRequestId, SessionConsumerResponse,
    SessionConsumerRoster, SessionConsumerScope, SessionConsumerStoreError,
    SessionConsumerTenantNfScope, SessionConsumerVoterAuthority, SessionKey, SessionLeaseManager,
    SessionOp, SessionOpResult, SessionQuorumConsumer, StateClass, StateType, StoreError,
    StoredSessionRecord,
};
use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};
use opc_types::SpiffeId;

use crate::ConsensusTestCluster;

const FIXTURE_VOTER_COUNT: usize = 3;
const FIXTURE_CLIENT_SPIFFE: &str =
    "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/prepared-fenced-fixture";

/// Bootstrap failure for [`AuthenticatedPreparedFencedTransitionFixture`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthenticatedPreparedFencedTransitionFixtureError {
    /// The caller supplied an invalid or empty application grant.
    #[error(transparent)]
    Grant(#[from] SessionConsumerAuthorizationGrantError),
    /// A durable journal or exact-voter activation operation failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The fixed persistent-client configuration was rejected.
    #[error(transparent)]
    PersistentClient(#[from] opc_session_net::PersistentSessionConsumerConfigError),
    /// The opaque local-AEAD facade could not be composed.
    #[error(transparent)]
    Facade(#[from] SessionConsumerPreparedFencedTransitionBackendError),
    /// One ephemeral authenticated listener could not start.
    #[error(transparent)]
    Listener(#[from] io::Error),
}

/// Failure while advancing the fixture's real authoritative store through a
/// caller-supplied successor transition.
///
/// This test-only control preserves the caller's exact request identity and
/// immutable deadline budget. It never exposes a prepared token, client, or
/// router and does not turn ambiguous delivery into a replay.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthenticatedPreparedFencedTransitionFixtureSuccessorError {
    /// Constructing a fresh authenticated facade for this semantic test
    /// control failed before the successor could be prepared.
    #[error(transparent)]
    Reopen(#[from] AuthenticatedPreparedFencedTransitionFixtureError),
    /// The opaque facade rejected preparation before an authoritative
    /// transition was dispatched.
    #[error(transparent)]
    Prepare(#[from] StoreError),
    /// The one permitted opaque dispatch did not return a confirmed outcome.
    #[error(transparent)]
    Execute(#[from] FencedTransitionExecuteError),
}

/// Paired authenticated fixture composition for one product test process.
///
/// It owns no additional authority: its general encrypted consumer backend,
/// opaque prepared-fenced facade, and facade reopener share the fixture's
/// exact authenticated three-voter client fleet, prepared journal, and local
/// sealing namespace. The physical clients, journal key, listener addresses,
/// and any prepared token remain private.
pub struct AuthenticatedPreparedFencedTransitionFixturePair<'fixture, P: ?Sized> {
    general_backend: AuthenticatedPreparedFencedTransitionFixtureGeneralBackend<P>,
    prepared_fenced_transition_facade: SessionConsumerPreparedFencedTransitionBackend,
    facade_reopener: AuthenticatedPreparedFencedTransitionFacadeReopener<'fixture, P>,
}

impl<P: ?Sized> fmt::Debug for AuthenticatedPreparedFencedTransitionFixturePair<'_, P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedPreparedFencedTransitionFixturePair(<redacted>)")
    }
}

/// Reopen-only capability for a fresh opaque facade over an existing fixture
/// journal.
///
/// This models a new product process. It can create a new facade connected to
/// the same authenticated voters and sealed prepared journal, but never
/// exposes a client, endpoint, router, journal credential, or raw prepared
/// request.
pub struct AuthenticatedPreparedFencedTransitionFacadeReopener<'fixture, P: ?Sized> {
    fixture: &'fixture AuthenticatedPreparedFencedTransitionFixture,
    provider: Arc<P>,
    backend_namespace: Arc<str>,
    journal: Arc<PreparedFencedTransitionJournal>,
}

impl<P: ?Sized> Clone for AuthenticatedPreparedFencedTransitionFacadeReopener<'_, P> {
    fn clone(&self) -> Self {
        Self {
            fixture: self.fixture,
            provider: Arc::clone(&self.provider),
            backend_namespace: Arc::clone(&self.backend_namespace),
            journal: Arc::clone(&self.journal),
        }
    }
}

impl<P: ?Sized> fmt::Debug for AuthenticatedPreparedFencedTransitionFacadeReopener<'_, P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedPreparedFencedTransitionFacadeReopener(<redacted>)")
    }
}

/// General encrypted durable consumer backend paired with the fixture's
/// opaque prepared-fenced facade.
///
/// This is intentionally a normal [`SessionBackend`] plus
/// [`SessionLeaseManager`] surface, so it satisfies
/// [`opc_session_store::SessionStoreBackend`]. Its private client fleet is
/// the exact same authenticated three-voter fleet used by the paired facade.
/// V1/V2 fenced-transition entry points deliberately retain the trait's
/// fail-closed defaults: only the opaque facade can prepare, dispatch, or
/// reopen a prepared fenced transition.
pub struct AuthenticatedPreparedFencedTransitionFixtureGeneralBackend<P: ?Sized> {
    inner: Arc<EncryptingSessionBackend<FixtureGeneralConsumerBackend, P>>,
    counters: Arc<FixtureGeneralConsumerCounters>,
}

impl<P: ?Sized> Clone for AuthenticatedPreparedFencedTransitionFixtureGeneralBackend<P> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            counters: Arc::clone(&self.counters),
        }
    }
}

impl<P: ?Sized> fmt::Debug for AuthenticatedPreparedFencedTransitionFixtureGeneralBackend<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("AuthenticatedPreparedFencedTransitionFixtureGeneralBackend(<redacted>)")
    }
}

/// Private ordinary-operation mTLS port retained inside the paired general
/// backend. Its three persistent clients share pools with the opaque facade;
/// none is exposed by the public testkit API.
#[derive(Clone)]
struct FixtureGeneralConsumerBackend {
    clients: Arc<[PersistentSessionConsumerClient]>,
    next_client: Arc<AtomicUsize>,
    ordinary_cas_fault: Arc<FixtureOrdinaryCasFault>,
}

impl FixtureGeneralConsumerBackend {
    fn new(
        clients: Vec<PersistentSessionConsumerClient>,
        ordinary_cas_fault: Arc<FixtureOrdinaryCasFault>,
    ) -> Self {
        debug_assert_eq!(clients.len(), FIXTURE_VOTER_COUNT);
        Self {
            clients: Arc::from(clients),
            next_client: Arc::new(AtomicUsize::new(0)),
            ordinary_cas_fault,
        }
    }

    fn client(&self) -> PersistentSessionConsumerClient {
        let index = self.next_client.fetch_add(1, Ordering::Relaxed) % self.clients.len();
        self.clients[index].clone()
    }
}

#[derive(Default)]
struct FixtureGeneralConsumerCounters {
    mutations: AtomicUsize,
    compare_and_set: AtomicUsize,
}

fn increment_fixture_counter(counter: &AtomicUsize) {
    let _ = counter.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
        Some(value.saturating_add(1))
    });
}

impl fmt::Debug for FixtureGeneralConsumerBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FixtureGeneralConsumerBackend(<redacted>)")
    }
}

/// A real three-voter authenticated consumer lab for downstream facade tests.
///
/// This is test-support only, but it uses the same production constructors as
/// an application: each listener receives a store-issued authorization
/// manifest, each client uses mTLS plus a topology-issued voter authority,
/// and the facade accepts only an opaque V1-prewarmed roster. The fixture
/// owns every lower layer and returns only an affine facade or a paired
/// ordinary backend whose V1 transition methods fail closed.
pub struct AuthenticatedPreparedFencedTransitionFixture {
    cluster: ConsensusTestCluster,
    roster: SessionConsumerRoster,
    grant: SessionConsumerAuthorizationGrant,
    pki: FixturePki,
    client_config: AuthenticatedClientConfig,
    voters: Vec<FixtureVoter>,
    lose_next_fenced_transition_response: Arc<AtomicBool>,
    fenced_transition_status_misses_remaining: Arc<AtomicUsize>,
    general_consumer_counters: Arc<FixtureGeneralConsumerCounters>,
    ordinary_cas_fault: Arc<FixtureOrdinaryCasFault>,
    listeners: Vec<SessionQuorumConsumerServerHandle>,
    _journal_directory: tempfile::TempDir,
    journal_path: PathBuf,
    journal_key: PreparedFencedTransitionJournalKey,
}

/// Copy-only aggregate observation of fixture transport activity.
///
/// It intentionally reveals neither endpoints nor request contents. Downstream
/// tests can use it to prove that an ambiguous mutation was recovered by
/// receipt status rather than a second mutation dispatch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuthenticatedPreparedFencedTransitionFixtureDiagnostics {
    fenced_transition_calls: usize,
    fenced_transition_status_calls: usize,
    forced_fenced_transition_status_misses: usize,
    general_mutation_calls: usize,
    general_compare_and_set_calls: usize,
}

/// Fixed, nonidentifying evidence from one ordinary CAS response-loss fault.
///
/// Request correlation compares the complete encrypted CAS body, its original
/// ID, and the exact consumer scope internally. No authority or payload value
/// is returned. Array slots identify only the fixture's three private voters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuthenticatedOrdinaryCasResponseLossEvidence {
    /// The authenticated handler received the exact client request.
    pub request_correlated: bool,
    /// The real consensus service returned CAS Success before suppression.
    pub durable_success: bool,
    /// The actual client returned OutcomeUnknown for that same request ID.
    pub client_outcome_unknown: bool,
    /// Server supervision dropped the suppressed-response future at timeout.
    pub suppressed_response_finished: bool,
    /// Physical dispatches of the original exact CAS, including any replay.
    pub target_cas_dispatches: usize,
    /// All ordinary mutation dispatches for the captured namespace key.
    pub namespace_mutation_dispatches: usize,
    /// All CAS dispatches for that key, including a different request ID.
    pub namespace_cas_dispatches: usize,
    /// Genuine durable read responses equal to the full encrypted replacement.
    pub exact_readbacks: [usize; FIXTURE_VOTER_COUNT],
    /// Exact-key read responses deliberately made unavailable, per voter.
    pub unavailable_readbacks: [usize; FIXTURE_VOTER_COUNT],
    /// Genuine exact read responses delivered after releasing the gate.
    pub delivered_exact_readbacks: usize,
    /// Real read responses still owned by a pending delivery gate.
    pub pending_readback_responses: usize,
    /// A request/result mismatch or unexpected real backend failure occurred.
    pub failed: bool,
}

/// Fixed failure category for ordinary CAS fault setup or evidence collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("ordinary CAS response-loss evidence unavailable")]
pub struct AuthenticatedOrdinaryCasResponseLossError;

/// Owned control for one ordinary committed-CAS lost-success/timeout fault.
///
/// The real server withholds only a successful exact CAS response until the
/// unchanged transport deadline. It never manufactures OutcomeUnknown. The
/// next matching durable reads are held across all three listeners. Dropping
/// this control makes held reads unavailable; existing listener supervision
/// owns and bounds the suppressed response without an additional task.
pub struct AuthenticatedOrdinaryCasResponseLoss {
    gate: Arc<FixtureOrdinaryCasGate>,
}

impl fmt::Debug for AuthenticatedOrdinaryCasResponseLoss {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedOrdinaryCasResponseLoss(<redacted>)")
    }
}

impl AuthenticatedOrdinaryCasResponseLoss {
    /// Await real committed success, the same client's unknown outcome, and
    /// an exact durable read stopped before its response reaches the caller.
    /// The test owner must supply its existing functional containment bound.
    pub async fn wait_for_pending_readback(
        &self,
    ) -> Result<
        AuthenticatedOrdinaryCasResponseLossEvidence,
        AuthenticatedOrdinaryCasResponseLossError,
    > {
        loop {
            let changed = self.gate.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let evidence = self.evidence();
            if evidence.failed {
                return Err(AuthenticatedOrdinaryCasResponseLossError);
            }
            if evidence.durable_success
                && evidence.client_outcome_unknown
                && evidence.suppressed_response_finished
                && evidence.pending_readback_responses != 0
            {
                return Ok(evidence);
            }
            changed.await;
        }
    }

    /// Release genuine exact read responses, or keep all matching reads
    /// unavailable through poison/successor cleanup. This does not replay CAS.
    pub fn release_readback(&self, exact: bool) {
        self.gate.release_readback(exact);
    }

    /// Return a coherent fixed-value snapshot without touching transport.
    pub fn evidence(&self) -> AuthenticatedOrdinaryCasResponseLossEvidence {
        self.gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .evidence
    }

    /// Verify released readback behavior on each existing private voter pool.
    ///
    /// These supplementary authenticated reads compare the real encrypted
    /// row internally and return only fixed evidence. They do not dispatch a
    /// mutation, fabricate a receipt, expose a key, or mint selector authority.
    /// Public selector operations remain responsible for protected decryption
    /// and acceptance. The owner must bound this diagnostic future.
    pub async fn verify_released_readback_on_all_voters(
        &self,
        exact: bool,
    ) -> Result<
        AuthenticatedOrdinaryCasResponseLossEvidence,
        AuthenticatedOrdinaryCasResponseLossError,
    > {
        let (clients, expected) = {
            let state = self
                .gate
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.readback != Some(exact)
                || state.evidence.failed
                || !state.evidence.client_outcome_unknown
            {
                return Err(AuthenticatedOrdinaryCasResponseLossError);
            }
            let target = state
                .target
                .as_ref()
                .ok_or(AuthenticatedOrdinaryCasResponseLossError)?;
            (
                Arc::clone(&target.clients),
                target.operation.new_record.clone(),
            )
        };
        for (voter, client) in clients.iter().enumerate() {
            let before = self.evidence();
            let observed = client.get(expected.key.clone()).await;
            let after = self.evidence();
            let result_matches = if exact {
                matches!(observed, Ok(Some(record)) if record == expected)
            } else {
                matches!(observed, Err(StoreError::BackendUnavailable(_)))
                    && after.unavailable_readbacks[voter] > before.unavailable_readbacks[voter]
            };
            if !result_matches
                || after.failed
                || after.exact_readbacks[voter] <= before.exact_readbacks[voter]
            {
                return Err(AuthenticatedOrdinaryCasResponseLossError);
            }
        }
        Ok(self.evidence())
    }
}

impl Drop for AuthenticatedOrdinaryCasResponseLoss {
    fn drop(&mut self) {
        self.gate.release_readback(false);
    }
}

#[derive(Default)]
struct FixtureOrdinaryCasFault {
    active: Mutex<Option<Weak<FixtureOrdinaryCasGate>>>,
}

impl FixtureOrdinaryCasFault {
    fn active(&self) -> Option<Arc<FixtureOrdinaryCasGate>> {
        self.active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(Weak::upgrade)
    }
}

struct FixtureOrdinaryCasGate {
    tenant_nf: SessionConsumerTenantNfScope,
    state_type: StateType,
    state: Mutex<FixtureOrdinaryCasState>,
    changed: tokio::sync::Notify,
}

#[derive(Default)]
struct FixtureOrdinaryCasState {
    target: Option<FixtureOrdinaryCasTarget>,
    evidence: AuthenticatedOrdinaryCasResponseLossEvidence,
    readback: Option<bool>,
}

struct FixtureOrdinaryCasTarget {
    scope: SessionConsumerScope,
    request_id: SessionConsumerRequestId,
    operation: CompareAndSet,
    clients: Arc<[PersistentSessionConsumerClient]>,
}

struct FixtureOrdinaryCasPending<'a> {
    gate: &'a FixtureOrdinaryCasGate,
    readback: bool,
}

impl Drop for FixtureOrdinaryCasPending<'_> {
    fn drop(&mut self) {
        let mut state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.readback {
            state.evidence.pending_readback_responses =
                state.evidence.pending_readback_responses.saturating_sub(1);
        } else {
            state.evidence.suppressed_response_finished = true;
        }
        drop(state);
        self.gate.changed.notify_waiters();
    }
}

#[derive(Clone, Copy)]
enum FixtureOrdinaryCasCall {
    Mutation,
    Readback,
    Other,
}

impl FixtureOrdinaryCasGate {
    fn select_client_request(
        &self,
        scope: SessionConsumerScope,
        request_id: SessionConsumerRequestId,
        operation: &CompareAndSet,
        clients: Arc<[PersistentSessionConsumerClient]>,
    ) -> bool {
        if operation.key.tenant != *self.tenant_nf.tenant()
            || operation.key.nf_kind != *self.tenant_nf.nf_kind()
            || operation.new_record.state_type != self.state_type
            || operation.new_record.state_class != StateClass::AuthoritativeSession
            || operation.expected_generation.is_none()
        {
            return false;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.target.is_some() || state.readback.is_some() {
            return false;
        }
        state.target = Some(FixtureOrdinaryCasTarget {
            scope,
            request_id,
            operation: operation.clone(),
            clients,
        });
        true
    }

    fn observe_client_result(
        &self,
        scope: SessionConsumerScope,
        request_id: SessionConsumerRequestId,
        operation: &CompareAndSet,
        result: &Result<CompareAndSetResult, SessionConsumerMutationError>,
    ) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let same_request = state.target.as_ref().is_some_and(|target| {
            target.scope == scope
                && target.request_id == request_id
                && target.operation == *operation
        });
        if same_request
            && state.evidence.durable_success
            && matches!(result, Err(SessionConsumerMutationError::OutcomeUnknown { request_id: observed }) if *observed == request_id)
        {
            state.evidence.client_outcome_unknown = true;
        } else {
            state.evidence.failed = true;
        }
        drop(state);
        self.changed.notify_waiters();
    }

    fn observe_server_request(&self, request: &SessionConsumerRequest) -> FixtureOrdinaryCasCall {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(target) = state.target.as_ref() else {
            return FixtureOrdinaryCasCall::Other;
        };
        if request.scope() != target.scope {
            return FixtureOrdinaryCasCall::Other;
        }
        let key = match request.operation() {
            SessionConsumerOperation::CompareAndSet { op } => &op.key,
            SessionConsumerOperation::Get { key }
            | SessionConsumerOperation::AcquireLease { key, .. } => key,
            SessionConsumerOperation::RenewLease { lease, .. }
            | SessionConsumerOperation::ReleaseLease { lease }
            | SessionConsumerOperation::DeleteFenced { lease }
            | SessionConsumerOperation::RefreshTtl { lease, .. } => lease.key(),
            _ => return FixtureOrdinaryCasCall::Other,
        };
        if key != &target.operation.key {
            return FixtureOrdinaryCasCall::Other;
        }
        if matches!(request.operation(), SessionConsumerOperation::Get { .. }) {
            return if state.evidence.durable_success {
                FixtureOrdinaryCasCall::Readback
            } else {
                FixtureOrdinaryCasCall::Other
            };
        }
        let same_request = request.request_id() == target.request_id;
        let same_body = matches!(request.operation(), SessionConsumerOperation::CompareAndSet { op } if **op == target.operation);
        state.evidence.namespace_mutation_dispatches = state
            .evidence
            .namespace_mutation_dispatches
            .saturating_add(1);
        if matches!(
            request.operation(),
            SessionConsumerOperation::CompareAndSet { .. }
        ) {
            state.evidence.namespace_cas_dispatches =
                state.evidence.namespace_cas_dispatches.saturating_add(1);
        }
        if same_request {
            if !same_body {
                state.evidence.failed = true;
                self.changed.notify_waiters();
                return FixtureOrdinaryCasCall::Other;
            }
            state.evidence.request_correlated = true;
            state.evidence.target_cas_dispatches =
                state.evidence.target_cas_dispatches.saturating_add(1);
            FixtureOrdinaryCasCall::Mutation
        } else {
            FixtureOrdinaryCasCall::Other
        }
    }

    fn observe_committed_success(&self, response: &SessionConsumerResponse) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let success = matches!(
            response,
            SessionConsumerResponse::CompareAndSet(Ok(CompareAndSetResult::Success))
        );
        if success && state.evidence.request_correlated && !state.evidence.durable_success {
            state.evidence.durable_success = true;
        } else {
            state.evidence.failed = true;
        }
        drop(state);
        self.changed.notify_waiters();
        success
    }

    async fn gate_readback(
        &self,
        voter: usize,
        response: SessionConsumerResponse,
    ) -> SessionConsumerResponse {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let exact = state.target.as_ref().is_some_and(|target| {
                matches!(&response, SessionConsumerResponse::Get(Ok(Some(record))) if *record == target.operation.new_record)
            });
            if !exact {
                state.evidence.failed = true;
                self.changed.notify_waiters();
                return SessionConsumerResponse::Get(Err(SessionConsumerStoreError::Unavailable));
            }
            state.evidence.exact_readbacks[voter] =
                state.evidence.exact_readbacks[voter].saturating_add(1);
            state.evidence.pending_readback_responses =
                state.evidence.pending_readback_responses.saturating_add(1);
        }
        let _pending = FixtureOrdinaryCasPending {
            gate: self,
            readback: true,
        };
        self.changed.notify_waiters();
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(exact) = state.readback {
                    if exact {
                        state.evidence.delivered_exact_readbacks =
                            state.evidence.delivered_exact_readbacks.saturating_add(1);
                        return response;
                    }
                    state.evidence.unavailable_readbacks[voter] =
                        state.evidence.unavailable_readbacks[voter].saturating_add(1);
                    return SessionConsumerResponse::Get(Err(
                        SessionConsumerStoreError::Unavailable,
                    ));
                }
            }
            changed.await;
        }
    }

    fn release_readback(&self, exact: bool) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .readback = Some(exact);
        self.changed.notify_waiters();
    }
}

impl AuthenticatedPreparedFencedTransitionFixtureDiagnostics {
    /// Number of physical fenced-transition application requests observed by
    /// the real listener fleet.
    pub const fn fenced_transition_calls(self) -> usize {
        self.fenced_transition_calls
    }

    /// Number of physical prepared-receipt status requests observed by the
    /// real listener fleet.
    pub const fn fenced_transition_status_calls(self) -> usize {
        self.fenced_transition_status_calls
    }

    /// Number of valid receipt responses that the fixture deliberately
    /// reported as transient misses. This does not identify a voter or reveal
    /// a receipt body.
    pub const fn forced_fenced_transition_status_misses(self) -> usize {
        self.forced_fenced_transition_status_misses
    }

    /// Number of ordinary general-backend mutation calls. This is separate
    /// from the opaque V1 facade count so product tests can prove they did not
    /// fall back to generic CAS/lease mutation during prepared recovery.
    pub const fn general_mutation_calls(self) -> usize {
        self.general_mutation_calls
    }

    /// Number of ordinary general-backend compare-and-set calls.
    pub const fn general_compare_and_set_calls(self) -> usize {
        self.general_compare_and_set_calls
    }
}

impl fmt::Debug for AuthenticatedPreparedFencedTransitionFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedPreparedFencedTransitionFixture(<redacted>)")
    }
}

impl<'fixture, P> AuthenticatedPreparedFencedTransitionFixturePair<'fixture, P>
where
    P: KeyProvider + Send + Sync + 'static + ?Sized,
{
    /// Clone the paired general durable consumer backend.
    ///
    /// The clone shares the authenticated three-voter pools, local sealing
    /// namespace, and ordinary-session authority with the facade held here.
    #[must_use]
    pub fn general_backend(&self) -> AuthenticatedPreparedFencedTransitionFixtureGeneralBackend<P> {
        self.general_backend.clone()
    }

    /// Borrow the initial opaque prepared-fenced facade.
    ///
    /// Use [`Self::into_parts`] when the product test must take ownership of
    /// the facade while retaining a fresh-process reopener.
    #[must_use]
    pub const fn prepared_fenced_transition_facade(
        &self,
    ) -> &SessionConsumerPreparedFencedTransitionBackend {
        &self.prepared_fenced_transition_facade
    }

    /// Clone the reopener for a simulated fresh product process.
    #[must_use]
    pub fn facade_reopener(
        &self,
    ) -> AuthenticatedPreparedFencedTransitionFacadeReopener<'fixture, P> {
        self.facade_reopener.clone()
    }

    /// Separate the paired general backend, initial facade, and reopener.
    ///
    /// This is the intended product-test composition boundary. The returned
    /// values share one underlying voter authority and journal/sealing scope;
    /// none reveals lower-level transport or prepared-request material.
    pub fn into_parts(
        self,
    ) -> (
        AuthenticatedPreparedFencedTransitionFixtureGeneralBackend<P>,
        SessionConsumerPreparedFencedTransitionBackend,
        AuthenticatedPreparedFencedTransitionFacadeReopener<'fixture, P>,
    ) {
        (
            self.general_backend,
            self.prepared_fenced_transition_facade,
            self.facade_reopener,
        )
    }
}

impl<'fixture, P> AuthenticatedPreparedFencedTransitionFacadeReopener<'fixture, P>
where
    P: KeyProvider + Send + Sync + 'static + ?Sized,
{
    /// Open a fresh opaque facade over the same authenticated voters and
    /// durable prepared-request journal.
    ///
    /// The resulting facade has no dispatch authority for a request prepared
    /// by a prior facade. Recovery remains receipt-only through the exact
    /// caller-owned transition identity.
    pub async fn reopen_prepared_fenced_transition_facade(
        &self,
    ) -> Result<
        SessionConsumerPreparedFencedTransitionBackend,
        AuthenticatedPreparedFencedTransitionFixtureError,
    > {
        self.fixture
            .open_local_aead_from_clients(
                self.fixture.persistent_clients()?,
                Arc::clone(&self.provider),
                self.backend_namespace.to_string(),
                Arc::clone(&self.journal),
            )
            .await
    }

    /// Advance the fixture's real authority through one caller-supplied
    /// successor transition.
    ///
    /// This semantic test control prepares and dispatches exactly once through
    /// a fresh opaque facade. It preserves the request's stable identity and
    /// caller-owned absolute deadline; an ambiguous outcome is returned as-is
    /// and is never replayed or replaced with a new identity.
    pub async fn advance_authoritative_successor(
        &self,
        request: FencedTransitionRequest,
        budget: PreparedCheckpointBudget,
    ) -> Result<FencedTransitionOutcome, AuthenticatedPreparedFencedTransitionFixtureSuccessorError>
    {
        let deadline = budget.original_deadline();
        let facade =
            tokio::time::timeout_at(deadline, self.reopen_prepared_fenced_transition_facade())
                .await
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "authenticated fixture successor deadline elapsed before dispatch".into(),
                    )
                })??;
        let mut prepared = facade.prepare_fenced_transition(request, budget).await?;
        Ok(prepared.execute_once().await?)
    }
}

#[async_trait]
impl<P> SessionBackend for AuthenticatedPreparedFencedTransitionFixtureGeneralBackend<P>
where
    P: KeyProvider + Send + Sync + 'static + ?Sized,
{
    fn restore_scan_cursor_profile(&self) -> Option<RestoreScanCursorProfile> {
        self.inner.restore_scan_cursor_profile()
    }

    async fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities().await
    }

    async fn preflight_record_expiry(
        &self,
        preflights: &[RecordExpiryPreflight],
    ) -> Result<(), StoreError> {
        self.inner.preflight_record_expiry(preflights).await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        self.inner.get(key).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        increment_fixture_counter(&self.counters.mutations);
        increment_fixture_counter(&self.counters.compare_and_set);
        self.inner.compare_and_set(op).await
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        increment_fixture_counter(&self.counters.mutations);
        self.inner.delete_fenced(lease).await
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        increment_fixture_counter(&self.counters.mutations);
        self.inner.refresh_ttl(lease, ttl).await
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        if ops.iter().any(|op| !matches!(op, SessionOp::Get { .. })) {
            increment_fixture_counter(&self.counters.mutations);
        }
        self.inner.batch(ops).await
    }

    async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        self.inner.scan_restore_records(request).await
    }
}

#[async_trait]
impl<P> SessionLeaseManager for AuthenticatedPreparedFencedTransitionFixtureGeneralBackend<P>
where
    P: KeyProvider + Send + Sync + 'static + ?Sized,
{
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        increment_fixture_counter(&self.counters.mutations);
        self.inner.acquire(key, owner, ttl).await
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        increment_fixture_counter(&self.counters.mutations);
        self.inner.renew(lease, ttl).await
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        increment_fixture_counter(&self.counters.mutations);
        self.inner.release(lease).await
    }
}

#[async_trait]
impl SessionBackend for FixtureGeneralConsumerBackend {
    fn restore_scan_cursor_profile(&self) -> Option<RestoreScanCursorProfile> {
        Some(RestoreScanCursorProfile::DurableOpaqueV1)
    }

    async fn capabilities(&self) -> BackendCapabilities {
        self.client()
            .capabilities()
            .await
            .unwrap_or_else(|_| BackendCapabilities::minimal())
    }

    async fn preflight_record_expiry(
        &self,
        preflights: &[RecordExpiryPreflight],
    ) -> Result<(), StoreError> {
        self.client()
            .preflight_record_expiry(preflights.to_vec())
            .await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        self.client().get(key.clone()).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        let client = self.client();
        let request_id = SessionConsumerRequestId::new();
        let fault = self.ordinary_cas_fault.active().filter(|gate| {
            gate.select_client_request(client.scope(), request_id, &op, Arc::clone(&self.clients))
        });
        let result = client.compare_and_set_with_id(request_id, &op).await;
        if let Some(fault) = fault {
            fault.observe_client_result(client.scope(), request_id, &op, &result);
        }
        result.map_err(fixture_mutation_error)
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        self.client()
            .delete_fenced_with_id(SessionConsumerRequestId::new(), lease)
            .await
            .map_err(fixture_mutation_error)
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        self.client()
            .refresh_ttl_with_id(SessionConsumerRequestId::new(), lease, ttl)
            .await
            .map_err(fixture_mutation_error)
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        self.client()
            .batch_with_id(SessionConsumerRequestId::new(), &ops)
            .await
            .map_err(fixture_mutation_error)
    }

    async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        self.client().scan_restore_records(request).await
    }
}

#[async_trait]
impl SessionLeaseManager for FixtureGeneralConsumerBackend {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        self.client()
            .acquire_with_id(SessionConsumerRequestId::new(), key, &owner, ttl)
            .await
            .map_err(fixture_lease_mutation_error)
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        self.client()
            .renew_with_id(SessionConsumerRequestId::new(), lease, ttl)
            .await
            .map_err(fixture_lease_mutation_error)
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        self.client()
            .release_with_id(SessionConsumerRequestId::new(), &lease)
            .await
            .map_err(fixture_lease_mutation_error)
    }
}

fn fixture_mutation_error(error: SessionConsumerMutationError) -> StoreError {
    match error {
        SessionConsumerMutationError::Store(error) => error,
        // Keep fixture diagnostics/error surfaces nonidentifying.  The typed
        // error has already established the no-frame-write classification;
        // exposing its transport detail would add no recovery value here.
        SessionConsumerMutationError::NotTransmitted { .. } => StoreError::BackendUnavailable(
            "authenticated fixture general mutation was not transmitted".into(),
        ),
        SessionConsumerMutationError::OutcomeUnknown { .. } => {
            StoreError::FencedTransitionOutcomeUnknown
        }
        _ => StoreError::BackendUnavailable(
            "authenticated fixture general mutation unavailable".into(),
        ),
    }
}

fn fixture_lease_mutation_error(error: SessionConsumerLeaseMutationError) -> LeaseError {
    match error {
        SessionConsumerLeaseMutationError::Lease(error) => error,
        // See `fixture_mutation_error`: retain the classification without
        // surfacing transport details from the authenticated client.
        SessionConsumerLeaseMutationError::NotTransmitted { .. } => {
            LeaseError::Backend("authenticated fixture general lease was not transmitted".into())
        }
        SessionConsumerLeaseMutationError::OutcomeUnknown { .. } => {
            LeaseError::OperationOutcomeUnavailable
        }
        _ => LeaseError::Backend("authenticated fixture general lease unavailable".into()),
    }
}

impl AuthenticatedPreparedFencedTransitionFixture {
    /// Start three real OpenRaft voters and their mutually-authenticated V1
    /// consumer listeners for exactly `scopes`.
    ///
    /// The fixture's consumer SVID is fixed and private. Callers grant only
    /// their test's exact tenant/NF scopes, then obtain an opaque facade with
    /// [`Self::open_local_aead`].
    pub async fn start(
        scopes: impl IntoIterator<Item = SessionConsumerTenantNfScope>,
    ) -> Result<Self, AuthenticatedPreparedFencedTransitionFixtureError> {
        Self::start_with_authority(scopes, false).await
    }

    /// Start the sealed consumer lab with immutable fixed durable authority.
    ///
    /// Consumer sockets use real mTLS and every voter has a distinct file-backed
    /// database. Raft peers remain in-process, placement explicitly allows reduced
    /// resilience, and snapshots use `PortableVerified`. This constructor does
    /// not qualify physical failure domains or strict fs-verity snapshots.
    pub async fn start_fixed_durable(
        scopes: impl IntoIterator<Item = SessionConsumerTenantNfScope>,
    ) -> Result<Self, AuthenticatedPreparedFencedTransitionFixtureError> {
        Self::start_with_authority(scopes, true).await
    }

    async fn start_with_authority(
        scopes: impl IntoIterator<Item = SessionConsumerTenantNfScope>,
        fixed: bool,
    ) -> Result<Self, AuthenticatedPreparedFencedTransitionFixtureError> {
        let client_identity = SpiffeId::new(FIXTURE_CLIENT_SPIFFE)
            .expect("fixture client SPIFFE is a complete workload identity");
        let grant = SessionConsumerAuthorizationGrant::try_new(client_identity, scopes)?;
        let cluster = if fixed {
            ConsensusTestCluster::start_fixed_durable().await
        } else {
            ConsensusTestCluster::start(FIXTURE_VOTER_COUNT).await
        };
        let roster = cluster.consumer_roster().clone();
        debug_assert_eq!(roster.voter_count(), FIXTURE_VOTER_COUNT);
        let pki = FixturePki::new();
        let client_config = pki.client_config(FIXTURE_CLIENT_SPIFFE);
        let lose_next_fenced_transition_response = Arc::new(AtomicBool::new(false));
        let fenced_transition_status_misses_remaining = Arc::new(AtomicUsize::new(0));
        let general_consumer_counters = Arc::new(FixtureGeneralConsumerCounters::default());
        let ordinary_cas_fault = Arc::new(FixtureOrdinaryCasFault::default());

        let store_indexes = (0..FIXTURE_VOTER_COUNT)
            .map(|index| (cluster.store(index).status().node_id, index))
            .collect::<BTreeMap<_, _>>();
        let mut voters = Vec::with_capacity(FIXTURE_VOTER_COUNT);
        let mut listeners = Vec::with_capacity(FIXTURE_VOTER_COUNT);
        for member in roster.consensus_members() {
            let authority = roster
                .voter(member.node_id())
                .expect("topology-issued roster member derives voter authority");
            let store_index = *store_indexes
                .get(&authority.node_id())
                .expect("every topology-issued voter has one cluster store");
            let service = Arc::new(FixtureConsumer::new(
                Arc::new(cluster.store(store_index).consumer_service()),
                lose_next_fenced_transition_response.clone(),
                fenced_transition_status_misses_remaining.clone(),
                Arc::clone(&ordinary_cas_fault),
                voters.len(),
            ));
            let (listener, address) =
                start_fixture_listener(&pki, &roster, &grant, &authority, service.clone()).await?;
            listeners.push(listener);
            voters.push(FixtureVoter {
                address,
                authority,
                service,
            });
        }

        let journal_directory =
            tempfile::tempdir().expect("create fixture prepared journal directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::set_permissions(
                journal_directory.path(),
                std::fs::Permissions::from_mode(0o700),
            )
            .expect("make fixture prepared journal directory private");
        }
        let journal_path = journal_directory.path().join("prepared-fenced.sqlite3");
        let journal_key = PreparedFencedTransitionJournalKey::from_bytes([0x43; 32]);
        PreparedFencedTransitionJournal::create_new(&journal_path, journal_key.clone())?;

        Ok(Self {
            cluster,
            roster,
            grant,
            pki,
            client_config,
            voters,
            lose_next_fenced_transition_response,
            fenced_transition_status_misses_remaining,
            general_consumer_counters,
            ordinary_cas_fault,
            listeners,
            _journal_directory: journal_directory,
            journal_path,
            journal_key,
        })
    }

    /// Construct a fresh local-AEAD affine facade from the fixture's existing
    /// durable journal.
    ///
    /// Calling this again after dropping a previous facade reopens the same
    /// journal, so [`SessionConsumerPreparedFencedTransitionBackend::recover_fenced_transition_status`]
    /// produces a status-only handle. No method exposes a physical backend or
    /// permits recovered dispatch.
    pub async fn open_local_aead<P>(
        &self,
        provider: Arc<P>,
        backend_namespace: impl Into<String>,
    ) -> Result<
        SessionConsumerPreparedFencedTransitionBackend,
        AuthenticatedPreparedFencedTransitionFixtureError,
    >
    where
        P: KeyProvider + Send + Sync + 'static + ?Sized,
    {
        self.open_local_aead_from_clients(
            self.persistent_clients()?,
            provider,
            backend_namespace,
            self.open_journal()?,
        )
        .await
    }

    /// Construct a paired ordinary durable backend and opaque prepared-fenced
    /// facade over the same authenticated three-voter authority.
    ///
    /// `into_parts` yields the ordinary backend, the initial affine facade,
    /// and a reopen-only capability for a simulated fresh process. All three
    /// share this fixture's exact journal path/key and local-AEAD namespace;
    /// no method reveals a client, a voter address, an activated roster, or a
    /// prepared transition token.
    pub async fn open_local_aead_pair<P>(
        &self,
        provider: Arc<P>,
        backend_namespace: impl Into<String>,
    ) -> Result<
        AuthenticatedPreparedFencedTransitionFixturePair<'_, P>,
        AuthenticatedPreparedFencedTransitionFixtureError,
    >
    where
        P: KeyProvider + Send + Sync + 'static + ?Sized,
    {
        let backend_namespace: Arc<str> = Arc::from(backend_namespace.into());
        let clients = self.persistent_clients()?;
        let journal = self.open_journal()?;
        let prepared_fenced_transition_facade = self
            .open_local_aead_from_clients(
                clients.clone(),
                Arc::clone(&provider),
                backend_namespace.to_string(),
                Arc::clone(&journal),
            )
            .await?;
        let general_backend = AuthenticatedPreparedFencedTransitionFixtureGeneralBackend {
            inner: Arc::new(
                EncryptingSessionBackend::new(
                    Arc::new(FixtureGeneralConsumerBackend::new(
                        clients,
                        Arc::clone(&self.ordinary_cas_fault),
                    )),
                    Arc::clone(&provider),
                    backend_namespace.to_string(),
                )
                .with_fenced_transition_journal(Arc::clone(&journal)),
            ),
            counters: Arc::clone(&self.general_consumer_counters),
        };
        Ok(AuthenticatedPreparedFencedTransitionFixturePair {
            general_backend,
            prepared_fenced_transition_facade,
            facade_reopener: AuthenticatedPreparedFencedTransitionFacadeReopener {
                fixture: self,
                provider,
                backend_namespace,
                journal,
            },
        })
    }

    /// Open an opaque general backend that retains the SDK's sealed payload
    /// protection proof, for public protected selector-namespace tests.
    ///
    /// Unlike the accounting facade returned by `open_local_aead_pair`, this
    /// value can enter APIs requiring `ProtectedSessionBackend`. It is the same
    /// SDK-owned local AEAD wrapper, with the same required exact-voter readiness
    /// activation. Its physical clients and cryptographic material stay private.
    pub async fn open_protected_local_aead<P>(
        &self,
        provider: Arc<P>,
        backend_namespace: impl Into<String>,
    ) -> Result<
        impl opc_session_store::ProtectedSessionBackend + Clone + 'static,
        AuthenticatedPreparedFencedTransitionFixtureError,
    >
    where
        P: KeyProvider + Send + Sync + 'static + ?Sized,
    {
        let pair = self
            .open_local_aead_pair(provider, backend_namespace)
            .await?;
        Ok(pair.general_backend.inner.as_ref().clone())
    }

    /// Hold the next ordinary authoritative update in the exact tenant/NF and
    /// state-type scope after its real consensus success. Call only after
    /// provisioning and the test's precise pre-CAS phase gate: creation CAS,
    /// other record types, leases, prepared transitions, and consensus traffic
    /// cannot consume this fault. The first matching client request privately
    /// fixes its complete encrypted body, key, ID, and consensus scope.
    ///
    /// This is a lost-success/unchanged-transport-timeout case, not an injected
    /// socket EOF. One live control per fixture prevents cross-test arming.
    pub fn hold_next_ordinary_cas_response(
        &self,
        tenant_nf: SessionConsumerTenantNfScope,
        state_type: StateType,
    ) -> Result<AuthenticatedOrdinaryCasResponseLoss, AuthenticatedOrdinaryCasResponseLossError>
    {
        let mut active = self
            .ordinary_cas_fault
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active.as_ref().and_then(Weak::upgrade).is_some() {
            return Err(AuthenticatedOrdinaryCasResponseLossError);
        }
        let gate = Arc::new(FixtureOrdinaryCasGate {
            tenant_nf,
            state_type,
            state: Mutex::new(FixtureOrdinaryCasState::default()),
            changed: tokio::sync::Notify::new(),
        });
        *active = Some(Arc::downgrade(&gate));
        Ok(AuthenticatedOrdinaryCasResponseLoss { gate })
    }

    fn open_journal(
        &self,
    ) -> Result<
        Arc<PreparedFencedTransitionJournal>,
        AuthenticatedPreparedFencedTransitionFixtureError,
    > {
        Ok(Arc::new(PreparedFencedTransitionJournal::open_existing(
            &self.journal_path,
            self.journal_key.clone(),
        )?))
    }

    fn persistent_clients(
        &self,
    ) -> Result<
        Vec<PersistentSessionConsumerClient>,
        AuthenticatedPreparedFencedTransitionFixtureError,
    > {
        self.voters
            .iter()
            .map(|voter| {
                PersistentSessionConsumerClient::try_from_stateless(
                    StatelessSessionConsumerClient::new(
                        voter.address,
                        rustls_pki_types::ServerName::IpAddress(voter.address.ip().into()),
                        voter.authority.clone(),
                        self.client_config.clone(),
                    ),
                    PersistentSessionConsumerConfig::default(),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(AuthenticatedPreparedFencedTransitionFixtureError::PersistentClient)
    }

    async fn open_local_aead_from_clients<P>(
        &self,
        clients: Vec<PersistentSessionConsumerClient>,
        provider: Arc<P>,
        backend_namespace: impl Into<String>,
        journal: Arc<PreparedFencedTransitionJournal>,
    ) -> Result<
        SessionConsumerPreparedFencedTransitionBackend,
        AuthenticatedPreparedFencedTransitionFixtureError,
    >
    where
        P: KeyProvider + Send + Sync + 'static + ?Sized,
    {
        let activated =
            SessionConsumerPreparedFencedTransitionBackend::persistent_exact_voter_prewarm_roster(
                clients,
            )
            .await?;
        Ok(
            SessionConsumerPreparedFencedTransitionBackend::persistent_encrypting(
                activated,
                provider,
                backend_namespace,
                journal,
            )?,
        )
    }

    /// Withhold the next successful fenced-transition response from whichever
    /// exact voter the opaque facade chooses.
    ///
    /// The wrapped service delegates the actual OpenRaft mutation first and
    /// only then withholds its response. This is therefore a real post-write
    /// response-loss condition, not a fabricated receipt or raw replay hook.
    pub fn lose_next_fenced_transition_response(&self) {
        self.lose_next_fenced_transition_response
            .store(true, Ordering::Release);
    }

    /// Report the next full three-voter receipt-observation round as misses.
    ///
    /// Each decorated listener still performs its real read against the
    /// OpenRaft-backed service; only a valid status response is replaced with
    /// a transient `NotFound` at the fixture boundary. Authentication,
    /// topology, and store errors are never masked. The next status round
    /// therefore exposes the same already-committed receipt without any
    /// mutation replay or voter identity being made public.
    pub fn force_next_fenced_transition_status_round_to_miss(&self) {
        self.fenced_transition_status_misses_remaining
            .store(FIXTURE_VOTER_COUNT, Ordering::Release);
    }

    /// Return redacted aggregate transport activity for no-replay assertions.
    pub fn diagnostics(&self) -> AuthenticatedPreparedFencedTransitionFixtureDiagnostics {
        AuthenticatedPreparedFencedTransitionFixtureDiagnostics {
            fenced_transition_calls: self
                .voters
                .iter()
                .map(|voter| voter.service.fenced_transition_calls.load(Ordering::SeqCst))
                .sum(),
            fenced_transition_status_calls: self
                .voters
                .iter()
                .map(|voter| {
                    voter
                        .service
                        .fenced_transition_status_calls
                        .load(Ordering::SeqCst)
                })
                .sum(),
            forced_fenced_transition_status_misses: self
                .voters
                .iter()
                .map(|voter| {
                    voter
                        .service
                        .forced_fenced_transition_status_misses
                        .load(Ordering::SeqCst)
                })
                .sum(),
            general_mutation_calls: self
                .general_consumer_counters
                .mutations
                .load(Ordering::SeqCst),
            general_compare_and_set_calls: self
                .general_consumer_counters
                .compare_and_set
                .load(Ordering::SeqCst),
        }
    }

    /// Observe bounded, numeric local storage costs without issuing a request.
    ///
    /// This is available only with Linux `test-control`; other configurations
    /// return `None`. The observation carries no authority, endpoints, payloads,
    /// or storage paths. Take it outside a timed request and compare its totals
    /// with a preceding observation from the same fixture incarnation.
    pub fn local_storage_timing(&self) -> io::Result<Option<serde_json::Value>> {
        #[cfg(all(target_os = "linux", feature = "test-control"))]
        {
            let mut observations = Vec::with_capacity(FIXTURE_VOTER_COUNT);
            for index in 0..FIXTURE_VOTER_COUNT {
                let costs = opc_session_store::test_support::consensus_local_wal_costs_for_test(
                    &self.cluster.store(index),
                )?;
                observations.push(costs.map(|costs| {
                    // Select only fixed numeric categories. Do not propagate
                    // experimental diagnostics or underlying error text.
                    serde_json::json!({
                        "voter_slot": index,
                        "groups": costs["groups"],
                        "requests": costs["requests"],
                        "sync_calls": costs["sync_calls"],
                        "admission_us": costs["admission_us"],
                        "admission_lock_wait_us": costs["admission_lock_wait_us"],
                        "projection_us": costs["projection_us"],
                        "write_us": costs["write_us"],
                        "intent_us": costs["intent_us"],
                        "data_sync_us": costs["data_sync_us"],
                        "publication_us": costs["publication_us"],
                        "queue_wait_us": costs["queue_wait_us"],
                        "submit_to_callback_us": costs["submit_to_callback_us"],
                        "application": costs["application"],
                        "checkpoint": costs["checkpoint"],
                    })
                }));
            }
            Ok(Some(serde_json::Value::from(observations)))
        }
        #[cfg(not(all(target_os = "linux", feature = "test-control")))]
        Ok(None)
    }

    /// Restart only the private authenticated listener frontends.
    ///
    /// Existing facades retain their old connections and should be dropped by
    /// the test before it opens a replacement facade. The fixture retains the
    /// exact roster, grants, stores, and private identities, so restarting a
    /// listener never gives a caller a reusable client or activation input.
    pub async fn restart_listeners(
        &mut self,
    ) -> Result<(), AuthenticatedPreparedFencedTransitionFixtureError> {
        for listener in self.listeners.drain(..) {
            listener.abort_and_wait().await;
        }
        for voter in &mut self.voters {
            let (listener, address) = start_fixture_listener(
                &self.pki,
                &self.roster,
                &self.grant,
                &voter.authority,
                voter.service.clone(),
            )
            .await?;
            voter.address = address;
            self.listeners.push(listener);
        }
        Ok(())
    }

    /// Abort listeners and shut down the fixture's three store engines.
    pub async fn shutdown(
        mut self,
    ) -> Result<(), AuthenticatedPreparedFencedTransitionFixtureError> {
        for listener in self.listeners.drain(..) {
            listener.abort_and_wait().await;
        }
        for index in 0..FIXTURE_VOTER_COUNT {
            self.cluster.store(index).shutdown().await?;
        }
        Ok(())
    }
}

impl Drop for AuthenticatedPreparedFencedTransitionFixture {
    fn drop(&mut self) {
        if let Some(fault) = self.ordinary_cas_fault.active() {
            fault.release_readback(false);
        }
        for listener in &self.listeners {
            listener.abort();
        }
    }
}

struct FixtureVoter {
    address: SocketAddr,
    authority: SessionConsumerVoterAuthority,
    service: Arc<FixtureConsumer>,
}

async fn start_fixture_listener(
    pki: &FixturePki,
    roster: &SessionConsumerRoster,
    grant: &SessionConsumerAuthorizationGrant,
    authority: &SessionConsumerVoterAuthority,
    service: Arc<FixtureConsumer>,
) -> Result<(SessionQuorumConsumerServerHandle, SocketAddr), io::Error> {
    let authorizer = SessionConsumerAuthorizer::try_new(
        roster
            .clone()
            .authorization_manifest(authority.node_id(), [grant.clone()])
            .expect("fixture roster constructs its exact local manifest"),
    )
    .expect("fixture local manifest constructs an mTLS authorizer");
    SessionQuorumConsumerServer::new(
        service,
        pki.server_config(authority.tls_identity()),
        authorizer,
    )
    .listen("127.0.0.1:0".parse().expect("fixture listener address"))
    .await
}

/// Response-loss decorator around the real store-owned quorum service.
struct FixtureConsumer {
    inner: Arc<dyn SessionQuorumConsumer>,
    lose_next_fenced_transition_response: Arc<AtomicBool>,
    fenced_transition_status_misses_remaining: Arc<AtomicUsize>,
    fenced_transition_calls: AtomicUsize,
    fenced_transition_status_calls: AtomicUsize,
    forced_fenced_transition_status_misses: AtomicUsize,
    ordinary_cas_fault: Arc<FixtureOrdinaryCasFault>,
    voter: usize,
}

impl FixtureConsumer {
    fn new(
        inner: Arc<dyn SessionQuorumConsumer>,
        lose_next_fenced_transition_response: Arc<AtomicBool>,
        fenced_transition_status_misses_remaining: Arc<AtomicUsize>,
        ordinary_cas_fault: Arc<FixtureOrdinaryCasFault>,
        voter: usize,
    ) -> Self {
        Self {
            inner,
            lose_next_fenced_transition_response,
            fenced_transition_status_misses_remaining,
            fenced_transition_calls: AtomicUsize::new(0),
            fenced_transition_status_calls: AtomicUsize::new(0),
            forced_fenced_transition_status_misses: AtomicUsize::new(0),
            ordinary_cas_fault,
            voter,
        }
    }
}

#[async_trait]
impl SessionQuorumConsumer for FixtureConsumer {
    async fn execute(
        &self,
        authorization: &SessionConsumerAuthorization,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        let ordinary_fault = self.ordinary_cas_fault.active();
        let ordinary_call = ordinary_fault
            .as_ref()
            .map_or(FixtureOrdinaryCasCall::Other, |gate| {
                gate.observe_server_request(&request)
            });
        let fenced_transition = matches!(
            request.operation(),
            opc_session_store::SessionConsumerOperation::FencedTransition { .. }
        );
        if fenced_transition {
            self.fenced_transition_calls.fetch_add(1, Ordering::SeqCst);
        }
        let fenced_transition_status = matches!(
            request.operation(),
            opc_session_store::SessionConsumerOperation::FencedTransitionStatus { .. }
        );
        if fenced_transition_status {
            self.fenced_transition_status_calls
                .fetch_add(1, Ordering::SeqCst);
        }
        let response = self.inner.execute(authorization, request).await;
        if let Some(gate) = ordinary_fault {
            match ordinary_call {
                FixtureOrdinaryCasCall::Mutation if gate.observe_committed_success(&response) => {
                    // Keep the actual successful response below the ordinary
                    // server boundary until its unchanged bounded deadline.
                    // Only the production client/server can classify timeout
                    // as OutcomeUnknown. No replacement receipt is invented.
                    let _pending = FixtureOrdinaryCasPending {
                        gate: &gate,
                        readback: false,
                    };
                    std::future::pending::<SessionConsumerResponse>().await;
                }
                FixtureOrdinaryCasCall::Readback => {
                    return gate.gate_readback(self.voter, response).await;
                }
                FixtureOrdinaryCasCall::Mutation | FixtureOrdinaryCasCall::Other => {}
            }
        }
        if fenced_transition_status
            && matches!(
                &response,
                SessionConsumerResponse::FencedTransitionStatus(Ok(_))
            )
            && self
                .fenced_transition_status_misses_remaining
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
        {
            self.forced_fenced_transition_status_misses
                .fetch_add(1, Ordering::SeqCst);
            return SessionConsumerResponse::FencedTransitionStatus(Ok(
                opc_session_store::SessionConsumerFencedTransitionStatus::NotFound,
            ));
        }
        if fenced_transition
            && self
                .lose_next_fenced_transition_response
                .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            std::future::pending::<SessionConsumerResponse>().await;
        }
        response
    }

    async fn watch(
        &self,
        authorization: &SessionConsumerAuthorization,
        scope: opc_session_store::SessionConsumerScope,
        start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        self.inner.watch(authorization, scope, start_sequence).await
    }
}

struct FixturePki {
    ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
}

impl FixturePki {
    fn new() -> Self {
        let key = rcgen::KeyPair::generate().expect("generate fixture CA key");
        let mut parameters = rcgen::CertificateParams::default();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "prepared fenced fixture CA");
        Self {
            ca: rcgen::CertifiedIssuer::self_signed(parameters, key)
                .expect("sign fixture CA certificate"),
        }
    }

    fn client_config(&self, identity: &str) -> AuthenticatedClientConfig {
        let (_sender, receiver) = tokio::sync::watch::channel(Some(self.identity_state(identity)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("build fixture client mTLS configuration")
    }

    fn server_config(&self, identity: &str) -> AuthenticatedServerConfig {
        let (_sender, receiver) = tokio::sync::watch::channel(Some(self.identity_state(identity)));
        TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("build fixture server mTLS configuration")
    }

    fn identity_state(&self, identity: &str) -> opc_identity::IdentityState {
        let mut parameters = rcgen::CertificateParams::default();
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "prepared fenced fixture leaf");
        parameters.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(identity).expect("fixture SPIFFE URI"),
        ));
        let now = time::OffsetDateTime::now_utc();
        parameters.not_before = now - time::Duration::days(1);
        parameters.not_after = now + time::Duration::days(1);
        let key = rcgen::KeyPair::generate().expect("generate fixture workload key");
        let certificate = parameters
            .signed_by(&key, &self.ca)
            .expect("sign fixture workload certificate");
        let certificates = parse_certs_pem(&(certificate.pem() + &self.ca.pem()))
            .expect("parse fixture certificate chain");
        let private_key = parse_key_pem(&key.serialize_pem()).expect("parse fixture private key");
        let mut bundles = TrustBundleSet::new();
        bundles.insert(TrustBundle {
            trust_domain: TrustDomain::new("test.example").expect("fixture trust domain"),
            certificates: parse_certs_pem(&self.ca.pem()).expect("parse fixture trust bundle"),
        });
        build_identity_state(certificates, private_key, bundles)
            .expect("construct fixture workload identity")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use bytes::Bytes;
    use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
    use opc_session_store::{
        EncryptedSessionPayload, FenceToken, FencedTransitionExecuteError, FencedTransitionLease,
        FencedTransitionMutation, FencedTransitionRequest, FencedTransitionRequestId,
        FencedTransitionStatus, Generation, OwnerId, PreparedCheckpointBudget, SessionKey,
        SessionKeyType, StateClass, StateType, StoredSessionRecord,
    };
    use opc_types::{NetworkFunctionKind, TenantId};

    fn fixture_tenant() -> TenantId {
        TenantId::new("prepared-fenced-fixture").expect("fixture tenant")
    }

    fn fixture_scope(tenant: TenantId) -> SessionConsumerTenantNfScope {
        SessionConsumerTenantNfScope::new(tenant, NetworkFunctionKind::smf())
    }

    fn fixture_provider(tenant: TenantId) -> Arc<MemoryKeyProvider> {
        let provider = Arc::new(MemoryKeyProvider::new());
        provider
            .insert_active_key(
                KeyId::new("prepared-fenced-fixture-active").expect("fixture key ID"),
                KeyPurpose::Session,
                tenant,
                Zeroizing::new([0x5a; AES_256_GCM_SIV_KEY_LEN]),
            )
            .expect("install fixture local AEAD key");
        provider
    }

    fn fixture_key(tenant: TenantId) -> SessionKey {
        SessionKey {
            tenant,
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"prepared-fenced-fixture-session")
                .try_into()
                .expect("fixture stable session ID"),
        }
    }

    fn fixture_request(
        request_id: FencedTransitionRequestId,
        tenant: TenantId,
    ) -> FencedTransitionRequest {
        let key = fixture_key(tenant);
        let owner = OwnerId::new("prepared-fenced-fixture-owner").expect("fixture owner");
        let lease = FencedTransitionLease::acquire(
            key.clone(),
            owner.clone(),
            FenceToken::new(0),
            Duration::from_secs(30),
        )
        .expect("fixture acquire lease");
        FencedTransitionRequest::new(
            request_id,
            lease.clone(),
            FencedTransitionMutation::create(StoredSessionRecord {
                key,
                generation: Generation::new(1),
                owner,
                fence: lease.committed_fence().expect("fixture committed fence"),
                state_class: StateClass::AuthoritativeSession,
                state_type: StateType::from_static("prepared-fenced-fixture"),
                expires_at: None,
                payload: EncryptedSessionPayload::new([0x2b]),
            }),
        )
        .expect("fixture create transition")
    }

    fn fixture_budget(deadline: tokio::time::Instant) -> PreparedCheckpointBudget {
        PreparedCheckpointBudget::new(deadline, Duration::from_millis(250))
            .expect("fixture immutable request budget")
    }

    fn assert_session_store_backend<T: opc_session_store::SessionStoreBackend>() {}

    #[tokio::test]
    async fn fixture_general_fallback_counters_cover_public_preflight_and_sealing_failures() {
        let tenant = fixture_tenant();
        let fixture =
            AuthenticatedPreparedFencedTransitionFixture::start([fixture_scope(tenant.clone())])
                .await
                .expect("start authenticated three-voter fixture");
        let provider = Arc::new(MemoryKeyProvider::new());
        let pair = fixture
            .open_local_aead_pair(provider, "fixture-fallback-accounting")
            .await
            .expect("compose paired authenticated fixture authority");
        let (general, _facade, _reopener) = pair.into_parts();
        let key = fixture_key(tenant);
        let owner = OwnerId::new("fixture-fallback-accounting-owner").expect("fixture owner");
        let lease = general
            .acquire(&key, owner.clone(), Duration::from_secs(30))
            .await
            .expect("seed one general lease");
        assert_eq!(fixture.diagnostics().general_mutation_calls(), 1);

        assert_eq!(
            general
                .renew(&lease, Duration::MAX)
                .await
                .expect_err("invalid TTL must fail before the physical backend"),
            LeaseError::InvalidSessionTtl
        );
        assert_eq!(fixture.diagnostics().general_mutation_calls(), 2);

        let fence = lease.fence();
        let error = general
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease,
                expected_generation: None,
                new_record: StoredSessionRecord {
                    key: key.clone(),
                    generation: Generation::new(1),
                    owner,
                    fence,
                    state_class: StateClass::AuthoritativeSession,
                    state_type: StateType::from_static("fixture-fallback-accounting"),
                    expires_at: None,
                    payload: EncryptedSessionPayload::new([0x2c]),
                },
            })
            .await
            .expect_err("missing local seal key must fail before physical CAS dispatch");
        assert!(matches!(error, StoreError::Crypto(_)));
        assert_eq!(fixture.diagnostics().general_mutation_calls(), 3);
        assert_eq!(fixture.diagnostics().general_compare_and_set_calls(), 1);

        general
            .batch(vec![SessionOp::Get { key }])
            .await
            .expect("read-only batch remains ordinary read traffic");
        assert_eq!(fixture.diagnostics().general_mutation_calls(), 3);
        assert_eq!(fixture.diagnostics().general_compare_and_set_calls(), 1);
    }

    #[tokio::test]
    async fn fixture_pair_shares_authenticated_authority_and_reopens_without_v1_lowering() {
        let tenant = fixture_tenant();
        let provider = fixture_provider(tenant.clone());
        let fixture =
            AuthenticatedPreparedFencedTransitionFixture::start([fixture_scope(tenant.clone())])
                .await
                .expect("start authenticated three-voter fixture");
        let pair = fixture
            .open_local_aead_pair(Arc::clone(&provider), "fixture-paired-authority")
            .await
            .expect("compose paired authenticated fixture authority");
        assert_session_store_backend::<
            AuthenticatedPreparedFencedTransitionFixtureGeneralBackend<MemoryKeyProvider>,
        >();
        let (general, facade, reopener) = pair.into_parts();
        let request_id = FencedTransitionRequestId::from_bytes([0x30; 16]);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut prepared = facade
            .prepare_fenced_transition(
                fixture_request(request_id, tenant.clone()),
                fixture_budget(deadline),
            )
            .await
            .expect("prepare through the initial opaque facade");
        prepared
            .execute_once()
            .await
            .expect("the opaque facade commits through the shared authority");

        let record = general
            .get(&fixture_key(tenant))
            .await
            .expect("the paired general mTLS backend reads the same authority")
            .expect("the opaque facade committed the authoritative record");
        assert_eq!(record.generation, Generation::new(1));
        assert_eq!(
            general
                .fenced_transition_capability()
                .await
                .expect("general backend reports its fail-closed V1 capability"),
            None,
            "the paired general backend cannot lower the opaque V1 route"
        );
        assert_eq!(fixture.diagnostics().general_mutation_calls(), 0);
        assert_eq!(fixture.diagnostics().general_compare_and_set_calls(), 0);

        drop(prepared);
        drop(facade);
        let reopened = reopener
            .reopen_prepared_fenced_transition_facade()
            .await
            .expect("a fresh process facade reopens the same journal");
        let recovery_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut recovered = reopened
            .recover_fenced_transition_status(request_id, fixture_budget(recovery_deadline))
            .await
            .expect("recover exact retained transition identity")
            .expect("the paired facade journal retains the prepared identity");
        let receipt = recovered
            .status_until_terminal(recovery_deadline)
            .await
            .expect("fresh facade recovery is status-only");
        assert!(matches!(receipt, FencedTransitionStatus::Recorded(result) if result.is_ok()));
        assert_eq!(
            fixture.diagnostics().fenced_transition_calls(),
            1,
            "recovery on the fresh facade never replays the original mutation"
        );

        drop(recovered);
        drop(reopened);
        drop(reopener);
        drop(general);
        fixture.shutdown().await.expect("shut down fixture");
    }

    #[tokio::test]
    async fn fixture_prepares_and_executes_a_real_authenticated_three_voter_transition() {
        let tenant = fixture_tenant();
        let fixture =
            AuthenticatedPreparedFencedTransitionFixture::start([fixture_scope(tenant.clone())])
                .await
                .expect("start authenticated three-voter fixture");
        let facade = fixture
            .open_local_aead(fixture_provider(tenant.clone()), "fixture-fresh")
            .await
            .expect("open opaque local-AEAD facade");
        let request_id = FencedTransitionRequestId::from_bytes([0x31; 16]);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut prepared = facade
            .prepare_fenced_transition(
                fixture_request(request_id, tenant),
                fixture_budget(deadline),
            )
            .await
            .expect("prepare through the production facade");

        prepared
            .execute_once()
            .await
            .expect("one real authenticated transition commits");
        assert_eq!(
            fixture.diagnostics().fenced_transition_calls(),
            1,
            "the fresh affine handle dispatches exactly one physical mutation"
        );

        drop(prepared);
        drop(facade);
        fixture.shutdown().await.expect("shut down fixture");
    }

    #[tokio::test]
    async fn fixture_recovers_a_real_lost_response_after_journal_reopen_without_replay() {
        let tenant = fixture_tenant();
        let provider = fixture_provider(tenant.clone());
        let mut fixture =
            AuthenticatedPreparedFencedTransitionFixture::start([fixture_scope(tenant.clone())])
                .await
                .expect("start authenticated three-voter fixture");
        let request_id = FencedTransitionRequestId::from_bytes([0x32; 16]);
        let facade = fixture
            .open_local_aead(Arc::clone(&provider), "fixture-recovery")
            .await
            .expect("open opaque local-AEAD facade");
        let mut prepared = facade
            .prepare_fenced_transition(
                fixture_request(request_id, tenant),
                fixture_budget(tokio::time::Instant::now() + Duration::from_secs(3)),
            )
            .await
            .expect("prepare through the production facade");

        fixture.lose_next_fenced_transition_response();
        assert_eq!(
            prepared.execute_once().await,
            Err(FencedTransitionExecuteError::OutcomeUnknown { request_id }),
            "the real service commits, then the fixture withholds only its response"
        );
        let after_ambiguous = fixture.diagnostics();
        assert_eq!(
            after_ambiguous.fenced_transition_calls(),
            1,
            "one real writer accepted the transition before its response was lost"
        );

        drop(prepared);
        drop(facade);

        fixture
            .restart_listeners()
            .await
            .expect("restart only the private authenticated frontends");

        let reopened = fixture
            .open_local_aead(provider, "fixture-recovery")
            .await
            .expect("reopen the same durable prepared journal through a new facade");
        let recovery_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut recovered = reopened
            .recover_fenced_transition_status(request_id, fixture_budget(recovery_deadline))
            .await
            .expect("recover exact durable prepared identity")
            .expect("journal retains the exact prepared identity");
        let receipt = recovered
            .status_until_terminal(recovery_deadline)
            .await
            .expect("receipt-only recovery converges across the live roster");
        assert!(
            matches!(receipt, FencedTransitionStatus::Recorded(result) if result.is_ok()),
            "receipt is the real committed transition, never a fabricated fixture state"
        );
        let after_recovery = fixture.diagnostics();
        assert_eq!(
            after_recovery.fenced_transition_calls(),
            after_ambiguous.fenced_transition_calls(),
            "reopened recovery issues no second mutation"
        );
        assert!(
            after_recovery.fenced_transition_status_calls()
                > after_ambiguous.fenced_transition_status_calls(),
            "reopened recovery observes the receipt through status-only transport"
        );

        drop(recovered);
        drop(reopened);
        fixture.shutdown().await.expect("shut down fixture");
    }

    #[tokio::test]
    async fn fixture_status_miss_round_converges_on_later_real_receipt_without_replay() {
        let tenant = fixture_tenant();
        let fixture =
            AuthenticatedPreparedFencedTransitionFixture::start([fixture_scope(tenant.clone())])
                .await
                .expect("start authenticated three-voter fixture");
        let facade = fixture
            .open_local_aead(fixture_provider(tenant.clone()), "fixture-status-round")
            .await
            .expect("open opaque local-AEAD facade");
        let request_id = FencedTransitionRequestId::from_bytes([0x33; 16]);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut prepared = facade
            .prepare_fenced_transition(
                fixture_request(request_id, tenant),
                fixture_budget(deadline),
            )
            .await
            .expect("prepare through the production facade");

        fixture.lose_next_fenced_transition_response();
        assert_eq!(
            prepared.execute_once().await,
            Err(FencedTransitionExecuteError::OutcomeUnknown { request_id }),
            "the fixture only enters receipt recovery after one real mutation lost its response"
        );
        let after_ambiguous = fixture.diagnostics();
        assert_eq!(
            after_ambiguous.fenced_transition_calls(),
            1,
            "the committed mutation is the only physical mutation before receipt polling"
        );

        fixture.force_next_fenced_transition_status_round_to_miss();
        let receipt = prepared
            .status_until_terminal(deadline)
            .await
            .expect("the next status round exposes the already-committed receipt");
        assert!(
            matches!(receipt, FencedTransitionStatus::Recorded(result) if result.is_ok()),
            "the later response is the real OpenRaft receipt"
        );
        let after_receipt = fixture.diagnostics();
        assert_eq!(
            after_receipt.fenced_transition_calls(),
            after_ambiguous.fenced_transition_calls(),
            "three forced receipt misses never replay the mutation"
        );
        assert_eq!(
            after_receipt.forced_fenced_transition_status_misses()
                - after_ambiguous.forced_fenced_transition_status_misses(),
            FIXTURE_VOTER_COUNT,
            "exactly one complete opaque voter round was reported as transient misses"
        );
        assert!(
            after_receipt.fenced_transition_status_calls()
                > after_ambiguous.fenced_transition_status_calls() + FIXTURE_VOTER_COUNT,
            "a later deterministic status observation reaches the committed receipt"
        );

        drop(prepared);
        drop(facade);
        fixture.shutdown().await.expect("shut down fixture");
    }
}
