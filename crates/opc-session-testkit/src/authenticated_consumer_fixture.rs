//! Production-shaped authenticated consumer fixture for downstream SDK tests.
//!
//! The fixture owns its OpenRaft voters, mTLS listeners, persistent clients,
//! and prepared-request journal. Its only consumer-facing output is the
//! opaque [`SessionConsumerPreparedFencedTransitionBackend`]; it deliberately
//! exposes no physical client, backend, prepared token, or activated roster.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use opc_identity::{
    build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle, TrustBundleSet, TrustDomain,
};
use opc_key::KeyProvider;
use opc_session_net::{
    PersistentSessionConsumerClient, PersistentSessionConsumerConfig, SessionConsumerAuthorizer,
    SessionConsumerPreparedFencedTransitionBackend,
    SessionConsumerPreparedFencedTransitionBackendError, SessionQuorumConsumerServer,
    SessionQuorumConsumerServerHandle, StatelessSessionConsumerClient,
};
use opc_session_store::{
    PreparedFencedTransitionJournal, PreparedFencedTransitionJournalKey,
    SessionConsumerAuthorization, SessionConsumerAuthorizationGrant,
    SessionConsumerAuthorizationGrantError, SessionConsumerChange, SessionConsumerRejection,
    SessionConsumerRequest, SessionConsumerResponse, SessionConsumerRoster,
    SessionConsumerStoreError, SessionConsumerTenantNfScope, SessionConsumerVoterAuthority,
    SessionQuorumConsumer, StoreError,
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

/// A real three-voter authenticated consumer lab for downstream facade tests.
///
/// This is test-support only, but it uses the same production constructors as
/// an application: each listener receives a store-issued authorization
/// manifest, each client uses mTLS plus a topology-issued voter authority,
/// and the facade accepts only an opaque V1-prewarmed roster. The fixture
/// owns every lower layer and returns only the affine facade.
pub struct AuthenticatedPreparedFencedTransitionFixture {
    cluster: ConsensusTestCluster,
    roster: SessionConsumerRoster,
    grant: SessionConsumerAuthorizationGrant,
    pki: FixturePki,
    client_config: AuthenticatedClientConfig,
    voters: Vec<FixtureVoter>,
    lose_next_fenced_transition_response: Arc<AtomicBool>,
    fenced_transition_status_misses_remaining: Arc<AtomicUsize>,
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
}

impl fmt::Debug for AuthenticatedPreparedFencedTransitionFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedPreparedFencedTransitionFixture(<redacted>)")
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
        let client_identity = SpiffeId::new(FIXTURE_CLIENT_SPIFFE)
            .expect("fixture client SPIFFE is a complete workload identity");
        let grant = SessionConsumerAuthorizationGrant::try_new(client_identity, scopes)?;
        let cluster = ConsensusTestCluster::start(FIXTURE_VOTER_COUNT).await;
        let roster = cluster.consumer_roster().clone();
        debug_assert_eq!(roster.voter_count(), FIXTURE_VOTER_COUNT);
        let pki = FixturePki::new();
        let client_config = pki.client_config(FIXTURE_CLIENT_SPIFFE);
        let lose_next_fenced_transition_response = Arc::new(AtomicBool::new(false));
        let fenced_transition_status_misses_remaining = Arc::new(AtomicUsize::new(0));

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
        let clients = self
            .voters
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
            .collect::<Result<Vec<_>, _>>()?;
        let activated =
            SessionConsumerPreparedFencedTransitionBackend::persistent_exact_voter_prewarm_roster(
                clients,
            )
            .await?;
        let journal = Arc::new(PreparedFencedTransitionJournal::open_existing(
            &self.journal_path,
            self.journal_key.clone(),
        )?);
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
        }
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
}

impl FixtureConsumer {
    fn new(
        inner: Arc<dyn SessionQuorumConsumer>,
        lose_next_fenced_transition_response: Arc<AtomicBool>,
        fenced_transition_status_misses_remaining: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            inner,
            lose_next_fenced_transition_response,
            fenced_transition_status_misses_remaining,
            fenced_transition_calls: AtomicUsize::new(0),
            fenced_transition_status_calls: AtomicUsize::new(0),
            forced_fenced_transition_status_misses: AtomicUsize::new(0),
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

    fn fixture_request(
        request_id: FencedTransitionRequestId,
        tenant: TenantId,
    ) -> FencedTransitionRequest {
        let key = SessionKey {
            tenant,
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"prepared-fenced-fixture-session")
                .try_into()
                .expect("fixture stable session ID"),
        };
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
