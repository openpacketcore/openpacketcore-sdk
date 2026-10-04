//! Fixed-roster publication reads over the real authenticated V2 transport.

use super::*;
use opc_session_net::{
    FencedMutationRosterEstablishedPublication as EstablishedPublication,
    FencedMutationRosterProviderAdapter as ProviderAdapter,
    FencedMutationRosterPublicationError as PublicationError,
};
use std::collections::VecDeque;

enum ReadFault {
    Pass,
    Rejected,
    ServerRejected(SessionConsumerRejection),
    Hold,
    Release,
}

type ReadTrace = Arc<Mutex<Vec<usize>>>;

#[derive(Default)]
pub(super) struct PublicationReadControl {
    faults: Mutex<VecDeque<ReadFault>>,
    trace: Mutex<Option<(usize, ReadTrace)>>,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl PublicationReadControl {
    pub(super) async fn intercept(
        &self,
        request: &SessionConsumerRequest,
    ) -> Option<SessionConsumerResponse> {
        if !matches!(
            request.operation(),
            SessionConsumerOperation::FencedMutationRosterCurrentPublicationAuthority { .. }
        ) {
            return None;
        }
        if let Some((voter, trace)) = self.trace.lock().expect("read trace").as_ref() {
            trace.lock().expect("read trace entries").push(*voter);
        }
        let fault = self.faults.lock().expect("read faults").pop_front();
        match fault {
            None | Some(ReadFault::Pass) => None,
            Some(ReadFault::ServerRejected(rejection)) => Some(SessionConsumerResponse::Rejected(rejection)),
            Some(ReadFault::Rejected) => Some(
                SessionConsumerResponse::FencedMutationRosterCurrentPublicationAuthority(
                    opc_session_store::SessionConsumerRosterCurrentPublicationAuthorityReadResponse::Rejected,
                ),
            ),
            Some(ReadFault::Release) => {
                self.entered.notify_one();
                self.release.notified().await;
                None
            }
            Some(ReadFault::Hold) => {
                self.entered.notify_one();
                std::future::pending().await
            }
        }
    }
}

#[derive(Default)]
struct PublicationProvider {
    status_calls: AtomicUsize,
    begin_calls: AtomicUsize,
    adopt_calls: AtomicUsize,
    fresh_calls: AtomicUsize,
}

impl PublicationProvider {
    fn counts(&self) -> [usize; 4] {
        [
            self.status_calls.load(Ordering::SeqCst),
            self.begin_calls.load(Ordering::SeqCst),
            self.adopt_calls.load(Ordering::SeqCst),
            self.fresh_calls.load(Ordering::SeqCst),
        ]
    }
}

#[async_trait]
impl EstablishedPublicationProvider for PublicationProvider {
    type Error = ();

    async fn status(
        &self,
        _call: &EstablishedPublicationCall<'_>,
    ) -> Result<PublicationProviderOutcome, Self::Error> {
        self.status_calls.fetch_add(1, Ordering::SeqCst);
        Ok(PublicationProviderOutcome::Absent)
    }

    async fn begin_publication(
        &self,
        call: &EstablishedPublicationCall<'_>,
    ) -> Result<PublicationProviderOutcome, Self::Error> {
        self.begin_calls.fetch_add(1, Ordering::SeqCst);
        Ok(PublicationProviderOutcome::Pending(
            PublicationEvidence::new(call, vec![0x91]).expect("exact pending evidence"),
        ))
    }

    async fn adopt(
        &self,
        call: &EstablishedPublicationCall<'_>,
    ) -> Result<PublicationProviderOutcome, Self::Error> {
        self.adopt_calls.fetch_add(1, Ordering::SeqCst);
        Ok(PublicationProviderOutcome::Published(
            PublicationEvidence::new(call, vec![0x91]).expect("exact published evidence"),
        ))
    }

    async fn publish_fresh_established(
        &self,
        call: &EstablishedPublicationCall<'_>,
    ) -> Result<PublicationProviderOutcome, Self::Error> {
        self.fresh_calls.fetch_add(1, Ordering::SeqCst);
        Ok(PublicationProviderOutcome::Published(
            PublicationEvidence::new(call, vec![0x91]).expect("exact fresh evidence"),
        ))
    }
}

struct Fixture {
    pki: Arc<TestPki>,
    client_spiffe: String,
    addresses: Vec<SocketAddr>,
    servers: Vec<AbortConsumerServerOnDrop>,
    transports: Vec<Arc<CommitThenLoseConsumerResponse>>,
    pools: Vec<PersistentSessionConsumerClient>,
    member_provider: Arc<SixMemberRosterEvidenceProvider>,
    publication_provider: Arc<PublicationProvider>,
    attestor: Arc<dyn FencedMutationRosterExecutorAttestor>,
    trace: ReadTrace,
    primary: usize,
    // Release fixture isolation after transport/service owners have dropped.
    fleet: ThreeVoterConsumerFleet,
}

impl Fixture {
    async fn start() -> Self {
        let pki = Arc::new(TestPki::new());
        let fleet = ThreeVoterConsumerFleet::start_fixed_durable_with_v2_roster_attestation(
            Arc::clone(&pki),
            ProductionRosterAttestationIssuer::trust_root(),
        )
        .await;
        fleet.wait_for_observed_leader().await;
        let client_spiffe = spiffe("publication-failover-client");
        let trace = Arc::new(Mutex::new(Vec::new()));
        let primary = 2;
        let mut servers = Vec::new();
        let mut addresses = Vec::new();
        let mut transports = Vec::new();
        let mut pools = Vec::new();
        let attestor = ProductionRosterAttestationIssuer::new(
            fleet.consensus_identity(primary),
            three_voter_authorizer(&fleet.stores[primary], &client_spiffe)
                .await
                .scope(),
        );
        for voter in 0..THREE_VOTER_COUNT {
            let authorizer = three_voter_authorizer(&fleet.stores[voter], &client_spiffe).await;
            let service = Arc::new(fleet.stores[voter].consumer_service());
            let transport = Arc::new(CommitThenLoseConsumerResponse::roster_passthrough(
                service.clone(),
                service,
            ));
            *transport.publication_reads.trace.lock().expect("trace") =
                Some((voter, Arc::clone(&trace)));
            let (server, address) = SessionQuorumConsumerServer::new(
                transport.clone(),
                pki.server_config(&three_voter_spiffe(voter)),
                authorizer,
            )
            .with_roster_v2_ingress(transport.clone(), attestor.clone())
            .listen("127.0.0.1:0".parse().expect("listener address"))
            .await
            .expect("V2 publication listener");
            pools.push(protected_roster_v2_persistent_client(
                &pki,
                address,
                &three_voter_spiffe(voter),
                &client_spiffe,
                fleet.voter_authority(voter),
            ));
            servers.push(AbortConsumerServerOnDrop::new(server));
            addresses.push(address);
            transports.push(transport);
        }
        Self {
            fleet,
            pki,
            client_spiffe,
            addresses,
            servers,
            transports,
            pools,
            member_provider: Arc::new(SixMemberRosterEvidenceProvider::new(attestor.clone())),
            publication_provider: Arc::new(PublicationProvider::default()),
            attestor,
            trace,
            primary,
        }
    }

    fn compose(&self) -> ProviderAdapter<PublicationProvider> {
        // Caller order is deliberately different from canonical roster order.
        self.compose_with_voters([1, 2, 0].map(|voter| self.pools[voter].clone()))
            .expect("compose V2 publication adapter")
    }

    fn compose_with_voters(
        &self,
        voters: impl IntoIterator<Item = PersistentSessionConsumerClient>,
    ) -> Result<ProviderAdapter<PublicationProvider>, opc_session_net::ProtectedRosterTransportError>
    {
        self.pools[self.primary]
            .clone()
            .into_fenced_mutation_roster_v2_provider_adapter_with_publication_voters(
                voters,
                Arc::clone(&self.member_provider),
                Arc::clone(&self.publication_provider),
                self.attestor.clone(),
                NonZeroUsize::new(3).expect("provider concurrency"),
            )
    }

    async fn establish(
        &self,
        adapter: &ProviderAdapter<PublicationProvider>,
        nonce: u8,
    ) -> EstablishedPublication {
        let mut key = test_key();
        key.stable_id = Bytes::from(vec![nonce]).try_into().expect("unique key");
        let owner = OwnerId::new("publication-failover-owner").expect("owner");
        let lease = consumer_client(
            &self.pki,
            self.addresses[self.primary],
            &three_voter_spiffe(self.primary),
            &self.client_spiffe,
            self.fleet.voter_authority(self.primary),
        )
        .acquire_with_id(
            SessionConsumerRequestId::from_bytes([nonce; 16]),
            key.clone(),
            owner.clone(),
            Duration::from_secs(60),
        )
        .await
        .expect("acquire absent lease");
        let state_type = StateType::from_static("publication-failover-established");
        let record = StoredSessionRecord {
            key,
            generation: Generation::new(1),
            owner,
            fence: lease.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: state_type.clone(),
            expires_at: None,
            payload: EncryptedSessionPayload::new([nonce]),
        };
        let checkpoint = EncryptedSessionPayload::encrypt(
            CountingKeyProvider::with_active_session_key().as_ref(),
            &record,
            "publication-failover",
        )
        .await
        .expect("seal checkpoint")
        .as_bytes()
        .to_vec();
        let proposal = AbsentAdmissionProposal::new(
            FencedMutationRosterProfile::v2(),
            RosterId::from_bytes([nonce; 16]).expect("roster ID"),
            vec![Member::new(
                0,
                MemberOperationId::from_bytes([nonce; 16]).expect("member ID"),
                vec![nonce],
                1,
            )
            .expect("member")],
            state_type,
            vec![nonce],
            checkpoint,
            vec![nonce],
        )
        .expect("absent proposal");
        let client = adapter.client();
        let mut admission = client
            .prepare_absent(lease, proposal)
            .expect("prepare admission");
        let mut active = match client.admit(&mut admission).await.expect("admit") {
            AdmissionOutcome::Admitted(active) => active,
            other => panic!("expected admitted roster: {other:?}"),
        };
        let mut member = active
            .member(MemberOrdinal::new(0).expect("ordinal"))
            .expect("member");
        assert!(matches!(
            client
                .prepare_member(&mut member)
                .await
                .expect("prepare member"),
            MemberPrepareOutcome::Prepared
        ));
        let proof = match client.execute(&mut member).await.expect("execute") {
            ExecuteOutcome::Conclusive(proof) => *proof,
            other => panic!("expected conclusive member: {other:?}"),
        };
        let proofs = CompleteProofSet::new(vec![proof]).expect("complete proofs");
        let mut terminal = client
            .prepare_terminal(active.for_terminal(), &proofs)
            .await
            .expect("prepare terminal");
        let publication = match client
            .terminalize(&mut terminal)
            .await
            .expect("terminalize")
        {
            TerminalizationOutcome::Committed(TerminalReceipt::Established(established)) => {
                established.into_publication()
            }
            other => panic!("expected established terminal: {other:?}"),
        };
        let sequence = self
            .fleet
            .application_sequences()
            .await
            .into_iter()
            .max()
            .expect("sequence");
        self.fleet.wait_all_application_sequences(sequence).await;
        publication
    }

    fn faults(&self, voter: usize, faults: impl IntoIterator<Item = ReadFault>) {
        *self.transports[voter]
            .publication_reads
            .faults
            .lock()
            .expect("faults") = faults.into_iter().collect();
    }

    fn take_trace(&self) -> Vec<usize> {
        std::mem::take(&mut *self.trace.lock().expect("trace"))
    }

    async fn quiesce(&mut self) {
        for pool in &self.pools {
            pool.shutdown().await;
        }
        for server in self.servers.drain(..) {
            server.abort_and_wait().await;
        }
        self.fleet.quiesce().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_failover_pre_and_post_reads_preserve_provider_calls() {
    let mut fixture = Fixture::start().await;
    let adapter = fixture.compose();
    let mut publication = fixture.establish(&adapter, 1).await;
    fixture.faults(2, (0..6).map(|_| ReadFault::Hold));
    let before = fixture.fleet.application_sequences().await;
    adapter
        .publish(&mut publication)
        .await
        .expect("alternate voter keeps publication available");
    assert_eq!(fixture.take_trace(), [2, 0, 2, 0, 2, 0, 2, 0, 2, 0, 2, 0]);
    assert_eq!(fixture.publication_provider.counts(), [1, 1, 1, 0]);
    assert_eq!(
        fixture.fleet.application_sequences().await,
        before,
        "publication reads add no consensus mutation"
    );
    for (voter, transport) in fixture.transports.iter().enumerate() {
        let expected = usize::from(voter == fixture.primary);
        assert_eq!(
            transport.roster_admission_calls.load(Ordering::SeqCst),
            expected
        );
        assert_eq!(
            transport.roster_terminal_calls.load(Ordering::SeqCst),
            expected
        );
    }
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_failover_survives_primary_listener_loss() {
    let mut fixture = Fixture::start().await;
    let adapter = fixture.compose();
    let mut publication = fixture.establish(&adapter, 1).await;
    let before = fixture.fleet.application_sequences().await;
    fixture
        .servers
        .remove(fixture.primary)
        .abort_and_wait()
        .await;
    adapter
        .publish(&mut publication)
        .await
        .expect("retained capsule publishes after original ingress disappears");
    assert_eq!(fixture.take_trace(), [0; 6]);
    assert_eq!(fixture.publication_provider.counts(), [1, 1, 1, 0]);
    assert_eq!(fixture.fleet.application_sequences().await, before);
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_failover_fresh_postcheck_and_canonical_alternates() {
    let mut fixture = Fixture::start().await;
    let adapter = fixture.compose();
    let mut publication = fixture.establish(&adapter, 1).await;
    fixture.faults(2, [ReadFault::Pass, ReadFault::Hold]);
    adapter
        .publish_fresh_established(&mut publication)
        .await
        .expect("fresh postcheck failover");
    assert_eq!(fixture.take_trace(), [2, 2, 0]);
    assert_eq!(fixture.publication_provider.counts(), [0, 0, 0, 1]);

    let mut publication = fixture.establish(&adapter, 2).await;
    fixture.faults(2, (0..6).map(|_| ReadFault::Hold));
    fixture.faults(0, (0..6).map(|_| ReadFault::Hold));
    adapter
        .publish(&mut publication)
        .await
        .expect("last fixed voter serves every barrier");
    assert_eq!(fixture.take_trace(), [2, 0, 1].repeat(6));
    assert_eq!(fixture.publication_provider.counts(), [1, 1, 1, 1]);
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_failover_rejection_is_terminal_before_and_after_effect() {
    let mut fixture = Fixture::start().await;
    let adapter = fixture.compose();
    let mut publication = fixture.establish(&adapter, 1).await;
    fixture.faults(2, [ReadFault::Rejected]);
    assert_eq!(
        adapter.publish(&mut publication).await,
        Err(PublicationError::AuthorityRejected)
    );
    assert_eq!(fixture.take_trace(), [2]);
    assert_eq!(fixture.publication_provider.counts(), [0, 0, 0, 0]);

    fixture.faults(2, [ReadFault::Hold]);
    fixture.faults(0, [ReadFault::Rejected]);
    assert_eq!(
        adapter.publish(&mut publication).await,
        Err(PublicationError::AuthorityRejected)
    );
    assert_eq!(fixture.take_trace(), [2, 0]);
    assert_eq!(fixture.publication_provider.counts(), [0, 0, 0, 0]);

    fixture.faults(2, [ReadFault::Pass, ReadFault::Rejected]);
    assert_eq!(
        adapter.publish_fresh_established(&mut publication).await,
        Err(PublicationError::RecoveryRequired)
    );
    assert_eq!(fixture.take_trace(), [2, 2]);
    assert_eq!(fixture.publication_provider.counts(), [0, 0, 0, 1]);
    assert_eq!(
        adapter.publish_fresh_established(&mut publication).await,
        Err(PublicationError::RecoveryRequired)
    );
    assert_eq!(
        fixture.publication_provider.counts(),
        [1, 0, 0, 1],
        "postcheck rejection cannot replay the fresh effect"
    );
    fixture.take_trace();

    let mut publication = fixture.establish(&adapter, 2).await;
    fixture.faults(2, [ReadFault::Pass, ReadFault::Hold]);
    fixture.faults(0, [ReadFault::Rejected]);
    assert_eq!(
        adapter.publish_fresh_established(&mut publication).await,
        Err(PublicationError::RecoveryRequired)
    );
    assert_eq!(fixture.take_trace(), [2, 2, 0]);
    assert_eq!(fixture.publication_provider.counts(), [1, 0, 0, 2]);
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_failover_all_unavailable_retains_same_capsule() {
    let mut fixture = Fixture::start().await;
    let adapter = fixture.compose();
    let mut publication = fixture.establish(&adapter, 1).await;
    for voter in 0..3 {
        fixture.faults(voter, [ReadFault::Hold]);
    }
    assert_eq!(
        adapter.publish(&mut publication).await,
        Err(PublicationError::AuthorityUnavailable)
    );
    assert_eq!(fixture.take_trace(), [2, 0, 1]);
    assert_eq!(fixture.publication_provider.counts(), [0, 0, 0, 0]);
    adapter
        .publish(&mut publication)
        .await
        .expect("retry same retained capsule after precheck unavailability");
    assert_eq!(fixture.take_trace(), [2; 6]);
    assert_eq!(fixture.publication_provider.counts(), [1, 1, 1, 0]);
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_failover_cancellation_does_not_advance_or_replay() {
    let mut fixture = Fixture::start().await;
    let adapter = fixture.compose();
    for (nonce, postcheck) in [(1, false), (2, true)] {
        let mut publication = fixture.establish(&adapter, nonce).await;
        if postcheck {
            fixture.faults(2, [ReadFault::Pass, ReadFault::Hold]);
        } else {
            fixture.faults(2, [ReadFault::Hold]);
        }
        fixture.faults(0, [ReadFault::Hold]);
        let mut publish = Box::pin(adapter.publish_fresh_established(&mut publication));
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::select! {
                _ = fixture.transports[0].publication_reads.entered.notified() => {}
                result = &mut publish => panic!("alternate read must stay pending: {result:?}"),
            }
        })
        .await
        .expect("alternate read entered");
        drop(publish);
        assert_eq!(
            fixture.take_trace(),
            if postcheck { vec![2, 2, 0] } else { vec![2, 0] }
        );
        let fresh_calls = usize::from(postcheck);
        assert_eq!(
            fixture.publication_provider.counts(),
            [usize::from(postcheck), 0, 0, fresh_calls]
        );
        assert_eq!(
            adapter.publish_fresh_established(&mut publication).await,
            Err(PublicationError::RecoveryRequired)
        );
        assert_eq!(
            fixture.publication_provider.counts(),
            [usize::from(postcheck) + 1, 0, 0, fresh_calls],
            "cancellation retains status/adopt-only authority"
        );
        assert_eq!(fixture.take_trace(), [2, 2]);
    }
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_failover_retains_original_primary_pool() {
    let mut fixture = Fixture::start().await;
    // Same authenticated voter, different pool, deliberately unusable endpoint.
    let duplicate_primary = protected_roster_v2_persistent_client(
        &fixture.pki,
        "127.0.0.1:0".parse().expect("unused endpoint"),
        &three_voter_spiffe(2),
        &fixture.client_spiffe,
        fixture.fleet.voter_authority(2),
    );
    let adapter = fixture
        .compose_with_voters([
            fixture.pools[1].clone(),
            duplicate_primary.clone(),
            fixture.pools[0].clone(),
        ])
        .expect("complete set identifies primary without replacing its pool");
    let mut publication = fixture.establish(&adapter, 1).await;
    adapter
        .publish(&mut publication)
        .await
        .expect("original primary remains usable");
    assert_eq!(fixture.take_trace(), [2; 6]);
    assert_eq!(fixture.publication_provider.counts(), [1, 1, 1, 0]);
    assert!(
        fixture.compose_with_voters(fixture.pools.clone()).is_err(),
        "original pool was claimed exactly once"
    );
    for pool in [duplicate_primary.clone(), fixture.pools[0].clone()] {
        pool.into_fenced_mutation_roster_v2_provider_adapter(
            Arc::clone(&fixture.member_provider),
            Arc::clone(&fixture.publication_provider),
            fixture.attestor.clone(),
            NonZeroUsize::new(3).expect("concurrency"),
        )
        .expect("read-only composition does not claim other pools' executors");
    }
    duplicate_primary.shutdown().await;
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_failover_rejects_invalid_rosters_before_claiming_pool() {
    let mut fixture = Fixture::start().await;
    let mut invalid_sets = vec![
        vec![],
        vec![fixture.pools[2].clone()],
        vec![fixture.pools[0].clone(), fixture.pools[1].clone()],
        vec![
            fixture.pools[0].clone(),
            fixture.pools[0].clone(),
            fixture.pools[2].clone(),
        ],
        vec![
            fixture.pools[0].clone(),
            fixture.pools[1].clone(),
            fixture.pools[2].clone(),
            fixture.pools[2].clone(),
        ],
    ];
    let ordinary = consumer_client(
        &fixture.pki,
        fixture.addresses[1],
        &three_voter_spiffe(1),
        &fixture.client_spiffe,
        fixture.fleet.voter_authority(1),
    );
    let foreign_identity = protected_roster_v2_persistent_client(
        &fixture.pki,
        fixture.addresses[1],
        &three_voter_spiffe(1),
        &spiffe("foreign-publication-client"),
        fixture.fleet.voter_authority(1),
    );
    for invalid_voter in [
        PersistentSessionConsumerClient::from_stateless(ordinary.clone()).expect("ordinary pool"),
        PersistentSessionConsumerClient::from_fenced_mutation_roster_stateless(ordinary)
            .expect("V1 pool"),
        foreign_identity,
    ] {
        invalid_sets.push(vec![
            fixture.pools[0].clone(),
            invalid_voter,
            fixture.pools[2].clone(),
        ]);
    }
    let members = (0..3).map(three_voter_member).collect::<Vec<_>>();
    let root = ProductionRosterAttestationIssuer::trust_root();
    let manifest = SessionReplicationManifest::try_new_with_epoch_and_roster_attestation_root(
        SessionClusterId::new("foreign-publication-roster").expect("cluster"),
        SessionConfigurationGeneration::new("foreign-roster-generation").expect("generation"),
        ConsensusConfigurationEpoch::new(1).expect("epoch"),
        members.clone(),
        Some(root.clone()),
    )
    .expect("foreign manifest");
    let topology = ValidatedQuorumTopology::try_from_fixed_durable_quorum_with_placement_policy(
        QuorumTopologyConfig::new_consensus(
            three_voter_replica_id(1),
            members,
            manifest.fixed_durable_quorum_consensus_identity(),
        )
        .with_roster_attestation_trust_root(root),
        manifest.placement_policy(),
    )
    .expect("foreign topology");
    let authority = topology
        .session_consumer_roster()
        .expect("foreign roster")
        .voter(topology.local_consensus_node_id().expect("foreign node"))
        .expect("foreign voter");
    invalid_sets.push(vec![
        fixture.pools[0].clone(),
        protected_roster_v2_persistent_client(
            &fixture.pki,
            fixture.addresses[1],
            &three_voter_spiffe(1),
            &fixture.client_spiffe,
            authority,
        ),
        fixture.pools[2].clone(),
    ]);
    for voters in invalid_sets {
        assert!(
            fixture.compose_with_voters(voters).is_err(),
            "invalid startup set must fail closed"
        );
    }
    let adapter = fixture.compose();
    assert!(
        fixture.take_trace().is_empty(),
        "validation performs no remote reads"
    );
    assert_eq!(fixture.publication_provider.counts(), [0; 4]);
    let mut publication = fixture.establish(&adapter, 1).await;
    adapter
        .publish(&mut publication)
        .await
        .expect("rejected construction did not consume executor claim");
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_failover_existing_constructor_remains_single_pool() {
    let mut fixture = Fixture::start().await;
    let adapter = fixture.pools[2]
        .clone()
        .into_fenced_mutation_roster_v2_provider_adapter(
            Arc::clone(&fixture.member_provider),
            Arc::clone(&fixture.publication_provider),
            fixture.attestor.clone(),
            NonZeroUsize::new(3).expect("concurrency"),
        )
        .expect("original single-pool constructor");
    let mut publication = fixture.establish(&adapter, 1).await;
    // Compatibility guard: opting into the new constructor must not change
    // the legacy single-pool classification of server-reported Unavailable.
    fixture.faults(
        2,
        [ReadFault::ServerRejected(
            SessionConsumerRejection::Unavailable,
        )],
    );
    assert_eq!(
        adapter.publish(&mut publication).await,
        Err(PublicationError::AuthorityUnavailable)
    );
    assert_eq!(fixture.take_trace(), [2]);
    assert_eq!(fixture.publication_provider.counts(), [0; 4]);
    adapter
        .publish(&mut publication)
        .await
        .expect("original single-pool retry behavior");
    assert_eq!(fixture.publication_provider.counts(), [1, 1, 1, 0]);
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_review_stalled_primary_leaves_time_for_alternate() {
    let mut fixture = Fixture::start().await;
    let adapter = fixture.compose();
    let mut publication = fixture.establish(&adapter, 1).await;
    fixture.faults(2, [ReadFault::Hold]);
    adapter
        .publish(&mut publication)
        .await
        .expect("stalled primary leaves alternate a budget");
    assert_eq!(fixture.take_trace(), [2, 0, 2, 2, 2, 2, 2]);
    assert_eq!(fixture.publication_provider.counts(), [1, 1, 1, 0]);
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_review_shutdown_alternate_does_not_end_traversal() {
    let mut fixture = Fixture::start().await;
    let adapter = fixture.compose();
    let mut publication = fixture.establish(&adapter, 1).await;
    fixture.pools[2].shutdown().await;
    fixture.pools[0].shutdown().await;
    adapter
        .publish(&mut publication)
        .await
        .expect("third pool can still answer");
    assert_eq!(fixture.take_trace(), [1; 6]);
    assert_eq!(fixture.publication_provider.counts(), [1, 1, 1, 0]);
    let snapshots = adapter.publication_pool_diagnostics();
    assert_eq!(snapshots.len(), 3);
    assert_eq!(snapshots[0], adapter.diagnostics_with_pool().pool);
    assert_eq!(snapshots[1], fixture.pools[0].diagnostics_without_io());
    assert_eq!(snapshots[2], fixture.pools[1].diagnostics_without_io());
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_review_all_server_rejections_are_terminal() {
    let mut fixture = Fixture::start().await;
    let adapter = fixture.compose();
    let mut publication = fixture.establish(&adapter, 1).await;
    fixture.pools[2].shutdown().await;
    for rejection in [
        SessionConsumerRejection::Unavailable,
        SessionConsumerRejection::MalformedRequest,
        SessionConsumerRejection::ScopeMismatch,
        SessionConsumerRejection::TopologyMismatch,
        SessionConsumerRejection::Unauthorized,
    ] {
        fixture.faults(0, [ReadFault::ServerRejected(rejection)]);
        assert_eq!(
            adapter.publish(&mut publication).await,
            Err(if rejection == SessionConsumerRejection::Unavailable {
                PublicationError::AuthorityUnavailable
            } else {
                PublicationError::AuthorityRejected
            })
        );
        assert_eq!(
            fixture.take_trace(),
            [0],
            "no third voter after a server rejection"
        );
        assert_eq!(fixture.publication_provider.counts(), [0; 4]);
    }
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_server_unavailable_preserves_retry_class_and_postcheck_recovery() {
    let mut fixture = Fixture::start().await;
    let adapter = fixture.compose();
    let mut publication = fixture.establish(&adapter, 1).await;
    fixture.faults(
        2,
        [ReadFault::ServerRejected(
            SessionConsumerRejection::Unavailable,
        )],
    );
    assert_eq!(
        adapter.publish(&mut publication).await,
        Err(PublicationError::AuthorityUnavailable)
    );
    assert_eq!(
        fixture.take_trace(),
        [2],
        "no alternate after server unavailability"
    );
    assert_eq!(fixture.publication_provider.counts(), [0; 4]);

    fixture.faults(
        2,
        [
            ReadFault::Pass,
            ReadFault::ServerRejected(SessionConsumerRejection::Unavailable),
        ],
    );
    assert_eq!(
        adapter.publish(&mut publication).await,
        Err(PublicationError::RecoveryRequired)
    );
    assert_eq!(
        fixture.take_trace(),
        [2, 2],
        "postcheck rejection is also terminal"
    );
    assert_eq!(fixture.publication_provider.counts(), [1, 0, 0, 0]);
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_hello_rejection_stops_before_healthy_alternate() {
    let mut fixture = Fixture::start().await;
    // TLS authenticates exactly voter 0, but its Hello authorizer names voter 1.
    // The real listener must return HelloRejected(TopologyMismatch), before
    // receiving any publication read and without a TLS authentication failure.
    let authorizer = three_voter_authorizer(&fixture.fleet.stores[1], &fixture.client_spiffe).await;
    let signer = ProductionRosterAttestationIssuer::new(
        fixture.fleet.consensus_identity(0),
        authorizer.scope(),
    );
    let transport = fixture.transports[0].clone();
    let (server, address) = SessionQuorumConsumerServer::new(
        transport.clone(),
        fixture.pki.server_config(&three_voter_spiffe(0)),
        authorizer,
    )
    .with_roster_v2_ingress(transport, signer)
    .listen("127.0.0.1:0".parse().expect("listener address"))
    .await
    .expect("Hello rejection listener");
    let server = AbortConsumerServerOnDrop::new(server);
    fixture.pools[0] = protected_roster_v2_persistent_client(
        &fixture.pki,
        address,
        &three_voter_spiffe(0),
        &fixture.client_spiffe,
        fixture.fleet.voter_authority(0),
    );
    let adapter = fixture.compose();
    let mut publication = fixture.establish(&adapter, 1).await;
    fixture.pools[2].shutdown().await;
    assert_eq!(
        adapter.publish(&mut publication).await,
        Err(PublicationError::AuthorityRejected)
    );
    assert!(
        fixture.take_trace().is_empty(),
        "no application read was dispatched"
    );
    let failures = fixture.pools[0].diagnostics_without_io();
    assert_eq!(failures.hello_attempts, 1, "real Hello: {failures:?}");
    assert_eq!(failures.hello_failures, 1, "Hello rejection: {failures:?}");
    assert_eq!(failures.tls_failures, 0, "TLS completed: {failures:?}");
    assert_eq!(fixture.pools[1].diagnostics_without_io().setup_attempts, 0);
    assert_eq!(fixture.publication_provider.counts(), [0; 4]);
    server.abort_and_wait().await;
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_review_primary_recovers_during_alternate_read() {
    let mut fixture = Fixture::start().await;
    let adapter = fixture.compose();
    let mut publication = fixture.establish(&adapter, 1).await;
    fixture.faults(2, [ReadFault::Release]);
    fixture.faults(0, [ReadFault::Release]);
    let mut publish = Box::pin(adapter.publish(&mut publication));
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            _ = fixture.transports[0].publication_reads.entered.notified() => {}
            result = &mut publish => panic!("alternate should be waiting: {result:?}"),
        }
    })
    .await
    .expect("primary share expired and alternate entered");
    // The expired client read cancels its server task. Recover the primary
    // by proving a fresh authenticated connection while the alternate stays
    // blocked; this must not route the current barrier back to the primary.
    fixture.transports[2].publication_reads.release.notify_one();
    assert!(
        fixture.pools[2]
            .prewarm()
            .await
            .expect("primary reconnects during barrier")
            .ready
    );
    assert!(
        futures_util::poll!(&mut publish).is_pending(),
        "late primary cannot satisfy alternate's barrier"
    );
    assert_eq!(fixture.publication_provider.counts(), [0; 4]);
    fixture.transports[0].publication_reads.release.notify_one();
    publish.await.expect("alternate completes the barrier");
    assert_eq!(fixture.take_trace(), [2, 0, 2, 2, 2, 2, 2]);
    assert_eq!(fixture.publication_provider.counts(), [1, 1, 1, 0]);
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_review_consensus_member_stopped() {
    let mut fixture = Fixture::start().await;
    let adapter = fixture.compose();
    let mut publication = fixture.establish(&adapter, 1).await;
    fixture.servers.remove(2).abort_and_wait().await;
    fixture.fleet.isolate(2).await;
    fixture.fleet.stores[2]
        .shutdown()
        .await
        .expect("stop primary consensus engine");
    fixture
        .fleet
        .wait_for_admitted_quorum_leader(&[0, 1], 0)
        .await;
    assert!(!fixture.fleet.stores[2].status().admitted);
    adapter
        .publish(&mut publication)
        .await
        .expect("two live consensus members serve publication");
    assert_eq!(fixture.take_trace(), [0; 6]);
    assert_eq!(fixture.publication_provider.counts(), [1, 1, 1, 0]);
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_review_retired_member_response_is_terminal() {
    let mut fixture = Fixture::start().await;
    let adapter = fixture.compose();
    let mut publication = fixture.establish(&adapter, 1).await;
    fixture.fleet.stores[2]
        .shutdown()
        .await
        .expect("retire primary while consumer listener remains reachable");
    assert_eq!(
        adapter.publish(&mut publication).await,
        Err(PublicationError::AuthorityRejected)
    );
    assert_eq!(fixture.take_trace(), [2]);
    assert_eq!(fixture.publication_provider.counts(), [0; 4]);
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_review_partitioned_alternate_cannot_serve_stale_current() {
    let mut fixture = Fixture::start().await;
    let adapter = fixture.compose();
    let mut publication = fixture.establish(&adapter, 1).await;
    fixture.pools[2].shutdown().await;
    fixture.fleet.isolate(0).await;
    fixture
        .fleet
        .wait_for_admitted_quorum_leader(&[1, 2], 0)
        .await;
    adapter
        .publish(&mut publication)
        .await
        .expect("partitioned reader times out before healthy reader answers");
    assert_eq!(fixture.take_trace(), [0, 1].repeat(6));
    assert_eq!(fixture.publication_provider.counts(), [1, 1, 1, 0]);
    fixture.quiesce().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_review_tls_alpn_and_io_alternates_are_retryable() {
    for fault in ["tls", "alpn", "io"] {
        let mut fixture = Fixture::start().await;
        let mut extra_server = None;
        let wrong_pki = TestPki::new();
        let address = match fault {
            "alpn" => {
                let authorizer =
                    three_voter_authorizer(&fixture.fleet.stores[0], &fixture.client_spiffe).await;
                let service = Arc::new(fixture.fleet.stores[0].consumer_service());
                // This listener negotiates ordinary consumer ALPNs only.
                let (server, address) = SessionQuorumConsumerServer::new(
                    service,
                    fixture.pki.server_config(&three_voter_spiffe(0)),
                    authorizer,
                )
                .listen("127.0.0.1:0".parse().expect("listener address"))
                .await
                .expect("ordinary listener");
                extra_server = Some(AbortConsumerServerOnDrop::new(server));
                address
            }
            "io" => "127.0.0.1:0".parse().expect("unreachable endpoint"),
            _ => fixture.addresses[0],
        };
        fixture.pools[0] = protected_roster_v2_persistent_client(
            if fault == "tls" {
                &wrong_pki
            } else {
                &fixture.pki
            },
            address,
            &three_voter_spiffe(0),
            &fixture.client_spiffe,
            fixture.fleet.voter_authority(0),
        );
        let adapter = fixture.compose();
        let mut publication = fixture.establish(&adapter, 1).await;
        fixture.pools[2].shutdown().await;
        adapter
            .publish(&mut publication)
            .await
            .unwrap_or_else(|error| panic!("{fault} alternate must be skipped: {error:?}"));
        assert_eq!(fixture.take_trace(), [1; 6]);
        assert_eq!(fixture.publication_provider.counts(), [1, 1, 1, 0]);
        let failures = fixture.pools[0].diagnostics_without_io();
        match fault {
            "tls" => assert!(
                failures.authentication >= 6,
                "real TLS failures: {failures:?}"
            ),
            "alpn" => assert!(failures.protocol >= 6, "real ALPN failures: {failures:?}"),
            "io" => assert!(
                failures.tcp_failures >= 6,
                "real TCP failures: {failures:?}"
            ),
            _ => unreachable!(),
        }
        if let Some(server) = extra_server {
            server.abort_and_wait().await;
        }
        fixture.quiesce().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_authority_review_attestation_root_mismatch_is_rejected() {
    let mut fixture = Fixture::start().await;
    let different_root = RosterAttestationTrustRootV1::new(
        [0xa2; 32],
        ProductionRosterAttestationIssuer::compressed_public_key(
            ProductionRosterAttestationIssuer::root_signing_key().verifying_key(),
        ),
    )
    .expect("different trust-root identity");
    // The attestation root is bound into the configuration identity. Build
    // the valid alternate identity with that changed root before composing.
    let members = (0..3).map(three_voter_member).collect::<Vec<_>>();
    let manifest = SessionReplicationManifest::try_new_with_epoch_and_roster_attestation_root(
        SessionClusterId::new("consumer-three-voter-transition").expect("cluster"),
        SessionConfigurationGeneration::new("consumer-three-voter-v1").expect("generation"),
        ConsensusConfigurationEpoch::new(1).expect("epoch"),
        members.clone(),
        Some(different_root.clone()),
    )
    .expect("root-bound manifest");
    let topology = ValidatedQuorumTopology::try_from_fixed_durable_quorum_with_placement_policy(
        QuorumTopologyConfig::new_consensus(
            three_voter_replica_id(0),
            members,
            manifest.fixed_durable_quorum_consensus_identity(),
        )
        .with_roster_attestation_trust_root(different_root),
        manifest.placement_policy(),
    )
    .expect("fixed topology bound to different root");
    let authority = topology
        .session_consumer_roster()
        .expect("roster")
        .voter(topology.local_consensus_node_id().expect("node"))
        .expect("voter");
    let foreign = protected_roster_v2_persistent_client(
        &fixture.pki,
        fixture.addresses[0],
        &three_voter_spiffe(0),
        &fixture.client_spiffe,
        authority,
    );
    assert!(fixture
        .compose_with_voters([
            foreign.clone(),
            fixture.pools[1].clone(),
            fixture.pools[2].clone()
        ])
        .is_err());
    let adapter = fixture.compose();
    let mut publication = fixture.establish(&adapter, 1).await;
    adapter
        .publish(&mut publication)
        .await
        .expect("failed construction did not claim primary");
    foreign.shutdown().await;
    fixture.quiesce().await;
}
