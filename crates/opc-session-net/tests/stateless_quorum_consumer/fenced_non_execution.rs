//! Non-execution settlement through real V2 ingress, signed provider receipts,
//! and the namespace actor's authenticated durable roster store.
//!
//! Tests submit no kernel mutations: the accepted-work case uses an
//! instrumented transport inside the real namespace actor.

#[path = "fenced_non_execution/accepted.rs"]
mod accepted;

#[path = "fenced_non_execution/established.rs"]
mod established;

use super::*;
use opc_ipsec_xfrm::{
    InstallPolicyRequest, IpAddress, LinuxXfrmBackend, NamespaceBoundLinuxXfrmBackend,
    PolicyParameters, QueryPolicyRequest, XfrmAction, XfrmBackend, XfrmDirection,
    XfrmObjectInstallRequest, XfrmObjectRosterAdmissionAuthority, XfrmObjectRosterDurableError,
    XfrmObjectRosterDurablePhase, XfrmObjectRosterGroupId, XfrmObjectRosterMemberPhase,
    XfrmObjectRosterMemberRequest, XfrmObjectRosterOperationGeneration,
    XfrmObjectRosterRecoveryProofKey, XfrmObjectRosterRecoveryStore, XfrmObjectRosterRequest,
    XfrmObjectRosterRestartOutcome, XfrmSelector,
};
use opc_session_net::{
    FencedMutationRosterAdmissionInput as AdmissionInput, FencedMutationRosterClient,
    FencedMutationRosterMemberProof as MemberProof,
};
use opc_session_store::fenced_mutation_roster::{
    RosterProviderOperationV1, RosterProviderOutcomeV1,
};

const WIDTH: u8 = 3;

#[derive(Clone, Copy)]
enum SettlementExecution {
    None,
    LoseAcknowledgement(u8),
    Conclusive,
}

struct RetainedMember {
    member: Member,
    group: XfrmObjectRosterGroupId,
    roster: XfrmObjectRosterRequest,
}

struct XfrmSettlementProvider {
    actor: NamespaceBoundLinuxXfrmBackend,
    store: XfrmObjectRosterRecoveryStore,
    issuer: Arc<ProductionRosterAttestationIssuer>,
    members: Vec<RetainedMember>,
    prepares: AtomicUsize,
    executions: AtomicUsize,
    reconciliations: AtomicUsize,
    compensations: AtomicUsize,
    execution: SettlementExecution,
    ready: Mutex<std::collections::HashMap<u8, XfrmObjectRosterAdmissionAuthority>>,
    bindings: Mutex<std::collections::HashMap<u8, [u8; 32]>>,
    observations: Mutex<Vec<(u8, &'static str)>>,
    _root: tempfile::TempDir,
}

impl XfrmSettlementProvider {
    async fn new(
        issuer: Arc<ProductionRosterAttestationIssuer>,
        width: u8,
        backend: LinuxXfrmBackend,
        execution: SettlementExecution,
    ) -> Arc<Self> {
        let root = tempfile::tempdir().expect("private durable provider directory");
        let (actor, store) = backend
            .bind_current_network_namespace_with_object_roster_recovery(
                root.path().join("rosters"),
                XfrmObjectRosterRecoveryProofKey::new([0x81; 32]).expect("synthetic proof key"),
            )
            .expect("bind the production namespace actor and authenticated store");
        let mut members = Vec::new();
        for ordinal in 0..width {
            // Group and store identity are chosen before the SDK descriptor,
            // rather than derived from a commitment that includes it.
            let group = XfrmObjectRosterGroupId::from_bytes([0xC1 + ordinal; 16]).unwrap();
            let request = XfrmObjectInstallRequest::Policy(InstallPolicyRequest {
                parameters: PolicyParameters {
                    selector: XfrmSelector::new(
                        IpAddress::Ipv4([192, 0, 2, ordinal + 1]),
                        IpAddress::Ipv4([198, 51, 100, ordinal + 1]),
                        17,
                    ),
                    direction: XfrmDirection::Out,
                    action: XfrmAction::Block,
                    priority: 100 + u32::from(ordinal),
                    templates: Vec::new(),
                    mark: None,
                    if_id: None,
                },
            });
            let roster =
                XfrmObjectRosterRequest::new(vec![XfrmObjectRosterMemberRequest::new(request)
                    .with_identity([0x91 + ordinal; 16], Self::generation())])
                .expect("retain the complete exact XFRM request");
            let identity = actor
                .register_durable_object_roster_settlement(
                    &store,
                    group,
                    Self::generation(),
                    &roster,
                )
                .await
                .expect("register exact provider binding before SDK admission");
            let mut descriptor = vec![0xA1, ordinal];
            descriptor.extend_from_slice(&identity.to_bytes());
            descriptor.extend_from_slice(&[0xC1 + ordinal; 16]);
            descriptor.extend_from_slice(&Self::generation().get().to_be_bytes());
            let member = Member::new(
                ordinal,
                MemberOperationId::from_bytes([0x91 + ordinal; 16]).expect("stable member"),
                descriptor,
                101 + u64::from(ordinal),
            )
            .expect("immutable SDK member");
            members.push(RetainedMember {
                member,
                group,
                roster: roster.with_settlement_identity(identity),
            });
        }
        Arc::new(Self {
            actor,
            store,
            issuer,
            members,
            prepares: AtomicUsize::new(0),
            executions: AtomicUsize::new(0),
            reconciliations: AtomicUsize::new(0),
            compensations: AtomicUsize::new(0),
            execution,
            ready: Mutex::new(std::collections::HashMap::new()),
            bindings: Mutex::new(std::collections::HashMap::new()),
            observations: Mutex::new(Vec::new()),
            _root: root,
        })
    }

    fn generation() -> XfrmObjectRosterOperationGeneration {
        // Deliberately unrelated to the SDK lease fence and member version.
        XfrmObjectRosterOperationGeneration::new(37).expect("provider generation")
    }

    fn binding(
        &self,
        call: &MemberCall<'_>,
    ) -> Result<(XfrmObjectRosterGroupId, &RetainedMember), ()> {
        call.validate_current_lease_at(Timestamp::now_utc())
            .map_err(|_| ())?;
        let retained = self.members.get(usize::from(call.ordinal())).ok_or(())?;
        if call.operation_id() != retained.member.operation_id()
            || call.descriptor() != retained.member.descriptor()
            || call.expected_version() != retained.member.expected_version()
        {
            return Err(());
        }
        let binding = call.fence_binding_commitment();
        let mut bindings = self.bindings.lock().map_err(|_| ())?;
        if *bindings.entry(call.ordinal()).or_insert(binding) != binding {
            return Err(());
        }
        Ok((retained.group, retained))
    }

    async fn observe(
        &self,
        call: &MemberCall<'_>,
        operation: RosterProviderOperationV1,
    ) -> Result<ProviderCallOutcome, ()> {
        let (group, retained) = self.binding(call)?;
        // Closing an unstarted binding does not join accepted actor work or
        // grant compensation. Missing storage is never a negative receipt.
        let observed = self
            .actor
            .fence_durable_object_roster(&self.store, group, Self::generation(), &retained.roster)
            .await;
        let label = match &observed {
            Ok(outcome) => outcome.as_str(),
            Err(XfrmObjectRosterDurableError::NotFound) => "not_found",
            Err(_) => "unavailable",
        };
        self.observations
            .lock()
            .map_err(|_| ())?
            .push((call.ordinal(), label));
        match observed {
            Ok(observed)
                if observed.closed_without_effect()
                    && observed.members().arity() == retained.roster.arity()
                    && observed.members().iter().all(|member| {
                        member.member_phase() == XfrmObjectRosterMemberPhase::Pending
                            && member.adjacent_proof_kind().is_none()
                    }) =>
            {
                let mut evidence = vec![0xB1];
                evidence.extend_from_slice(&call.fence_binding_commitment());
                self.issuer.provider_receipt(
                    call,
                    operation,
                    RosterProviderOutcomeV1::NotAppliedReconciled,
                    evidence,
                )
            }
            Ok(observed)
                if observed.phase() == XfrmObjectRosterDurablePhase::Applied
                    && operation != RosterProviderOperationV1::Reconcile =>
            {
                // Join the real actor through exact readback before signing
                // Applied. Leave cleanup authority intact for guarded abort.
                for ordinal in 0..retained.roster.arity() {
                    let XfrmObjectInstallRequest::Policy(request) =
                        retained.roster.member(ordinal).ok_or(())?.request()
                    else {
                        return Err(());
                    };
                    let parameters = &request.parameters;
                    let observed = self
                        .actor
                        .query_policy(QueryPolicyRequest::new(
                            parameters.selector.clone(),
                            parameters.direction,
                        ))
                        .await
                        .map_err(|_| ())?;
                    if observed != *parameters {
                        return Ok(ProviderCallOutcome::outcome_unknown());
                    }
                }
                let mut evidence = vec![0xB3];
                evidence.extend_from_slice(&call.fence_binding_commitment());
                self.issuer.provider_receipt(
                    call,
                    operation,
                    RosterProviderOutcomeV1::AppliedAdopted,
                    evidence,
                )
            }
            Err(XfrmObjectRosterDurableError::NotFound) => Ok(ProviderCallOutcome::not_found()),
            _ => Ok(ProviderCallOutcome::outcome_unknown()),
        }
    }

    async fn release_aborted(
        &self,
        receipt: &opc_session_net::FencedMutationRosterAbortedTerminal,
    ) {
        {
            let bindings = self.bindings.lock().unwrap();
            for retained in &self.members {
                assert_eq!(
                    receipt.settled_member_binding(
                        MemberOrdinal::new(retained.member.ordinal()).unwrap()
                    ),
                    bindings.get(&retained.member.ordinal()).copied(),
                    "release requires this exact admission/member terminal receipt",
                );
            }
        }
        for retained in &self.members {
            self.actor
                .release_durable_object_roster_settlement(
                    &self.store,
                    retained.group,
                    Self::generation(),
                    &retained.roster,
                )
                .await
                .expect("terminal receipt releases settlement retention");
        }
    }
}

#[async_trait]
impl MemberProvider for XfrmSettlementProvider {
    type Error = ();

    async fn prepare(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        let (group, retained) = self.binding(call)?;
        let authority = self
            .actor
            .prepare_durable_object_roster(
                &self.store,
                group,
                Self::generation(),
                retained.roster.clone(),
            )
            .await
            .map_err(|_| ())?;
        // The positive control models losing a prepared, never-run owner.
        // Dropping the affine authority permits ordinary zero-effect recovery.
        if matches!(self.execution, SettlementExecution::Conclusive)
            || matches!(self.execution, SettlementExecution::LoseAcknowledgement(ordinal) if ordinal == call.ordinal())
        {
            self.ready
                .lock()
                .map_err(|_| ())?
                .insert(call.ordinal(), authority);
        } else {
            drop(authority);
        }
        Ok(ProviderCallOutcome::prepared_not_run())
    }

    async fn execute(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        self.binding(call)?;
        let authority = self
            .ready
            .lock()
            .map_err(|_| ())?
            .remove(&call.ordinal())
            .ok_or(())?;
        self.actor
            .run_durable_object_roster(authority)
            .await
            .map_err(|_| ())?;
        if matches!(self.execution, SettlementExecution::Conclusive) {
            return self.issuer.provider_receipt(
                call,
                RosterProviderOperationV1::Execute,
                RosterProviderOutcomeV1::AppliedExecuted,
                vec![0xB4, call.ordinal()],
            );
        }
        // The effect is durable, but its SDK acknowledgement is deliberately lost.
        Ok(ProviderCallOutcome::outcome_unknown())
    }

    async fn status(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.observe(call, RosterProviderOperationV1::Status).await
    }

    async fn adopt(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.observe(call, RosterProviderOperationV1::Adopt).await
    }

    async fn reconcile_member(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.reconciliations.fetch_add(1, Ordering::SeqCst);
        self.observe(call, RosterProviderOperationV1::Reconcile)
            .await
    }

    async fn compensate_member(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        let (group, retained) = self.binding(call)?;
        self.compensations.fetch_add(1, Ordering::SeqCst);
        let observed = self
            .actor
            .recover_durable_object_roster(&self.store, group, Self::generation(), &retained.roster)
            .await
            .map_err(|_| ())?;
        if !matches!(
            observed,
            XfrmObjectRosterRestartOutcome::OwnedResidueRetired { .. }
                | XfrmObjectRosterRestartOutcome::RolledBack { .. }
                | XfrmObjectRosterRestartOutcome::Retired { .. }
        ) {
            return Ok(ProviderCallOutcome::outcome_unknown());
        }
        let mut evidence = vec![0xB2];
        evidence.extend_from_slice(&call.fence_binding_commitment());
        self.issuer.provider_receipt(
            call,
            RosterProviderOperationV1::Compensate,
            RosterProviderOutcomeV1::CompensatedReconciled,
            evidence,
        )
    }
}

struct SettlementFixture {
    fleet: ThreeVoterConsumerFleet,
    server: SessionQuorumConsumerServerHandle,
    shutdown_client: PersistentSessionConsumerClient,
    client: FencedMutationRosterClient,
    provider: Arc<XfrmSettlementProvider>,
    transport: Arc<CommitThenLoseConsumerResponse>,
    input: AdmissionInput,
    key: SessionKey,
    checkpoint: Vec<u8>,
    sequence_before: u64,
}

impl SettlementFixture {
    async fn start(lose_admission: bool) -> Self {
        Self::start_with_backend(lose_admission, WIDTH, LinuxXfrmBackend::new(), None).await
    }

    async fn start_with_backend(
        lose_admission: bool,
        width: u8,
        backend: LinuxXfrmBackend,
        run_member: Option<u8>,
    ) -> Self {
        Self::start_with_execution(
            lose_admission,
            width,
            backend,
            run_member.map_or(
                SettlementExecution::None,
                SettlementExecution::LoseAcknowledgement,
            ),
        )
        .await
    }

    async fn start_with_execution(
        lose_admission: bool,
        width: u8,
        backend: LinuxXfrmBackend,
        execution: SettlementExecution,
    ) -> Self {
        let pki = Arc::new(TestPki::new());
        let fleet = ThreeVoterConsumerFleet::start_fixed_durable_with_v2_roster_attestation(
            Arc::clone(&pki),
            ProductionRosterAttestationIssuer::trust_root(),
        )
        .await;
        let (leader, _, _) = fleet.wait_for_observed_leader().await;
        let server_spiffe = three_voter_spiffe(leader);
        let client_spiffe = spiffe("fenced-non-execution-client");
        let authorizer = three_voter_authorizer(&fleet.stores[leader], &client_spiffe).await;
        let voter_authority = fleet.voter_authority(leader);
        let issuer = ProductionRosterAttestationIssuer::new(
            fleet.consensus_identity(leader),
            authorizer.scope(),
        );
        let ingress: Arc<dyn RosterIngressSigner> = issuer.clone();
        let attestor: Arc<dyn FencedMutationRosterExecutorAttestor> = issuer.clone();
        let service = Arc::new(fleet.stores[leader].consumer_service());
        let transport = Arc::new(CommitThenLoseConsumerResponse::roster_loss(
            service.clone(),
            service,
            lose_admission,
            true,
        ));
        let (server, address) = SessionQuorumConsumerServer::new(
            transport.clone(),
            pki.server_config(&server_spiffe),
            authorizer,
        )
        .with_roster_v2_ingress(transport.clone(), ingress)
        .listen("127.0.0.1:0".parse::<SocketAddr>().expect("test listener"))
        .await
        .expect("V2 settlement ingress");
        let key = test_key();
        let owner = OwnerId::new("fenced-non-execution-owner").expect("synthetic owner");
        let lease = consumer_client(
            &pki,
            address,
            &server_spiffe,
            &client_spiffe,
            voter_authority.clone(),
        )
        .acquire_with_id(
            SessionConsumerRequestId::from_bytes([0x82; 16]),
            key.clone(),
            owner.clone(),
            Duration::from_secs(60),
        )
        .await
        .expect("original absent-predecessor lease");
        let sequence_before = *fleet.application_sequences().await.iter().max().unwrap();
        fleet.wait_all_application_sequences(sequence_before).await;
        let persistent = protected_roster_v2_persistent_client(
            &pki,
            address,
            &server_spiffe,
            &client_spiffe,
            voter_authority,
        );
        let shutdown_client = persistent.clone();
        let provider = XfrmSettlementProvider::new(issuer, width, backend, execution).await;
        let adapter = persistent
            .into_fenced_mutation_roster_v2_provider_adapter(
                Arc::clone(&provider),
                Arc::new(EstablishedPublicationEvidenceProvider::default()),
                attestor,
                // The per-scope gate reserves ceil(global / 2) slots; keep
                // two available for the held execute and concurrent closure.
                NonZeroUsize::new(usize::from(width.max(3))).unwrap(),
            )
            .expect("production signed provider adapter");
        let client = adapter.client().clone();
        let state_type = StateType::from_static("fenced-non-execution-created");
        let checkpoint = EncryptedSessionPayload::encrypt(
            CountingKeyProvider::with_active_session_key().as_ref(),
            &StoredSessionRecord {
                key: key.clone(),
                generation: Generation::new(1),
                owner,
                fence: lease.fence(),
                state_class: StateClass::AuthoritativeSession,
                state_type: state_type.clone(),
                expires_at: None,
                payload: EncryptedSessionPayload::new([0x83]),
            },
            "fenced-non-execution",
        )
        .await
        .expect("exact sealed absent-predecessor checkpoint")
        .as_bytes()
        .to_vec();
        let proposal = AbsentAdmissionProposal::new(
            FencedMutationRosterProfile::v2(),
            RosterId::from_bytes([0x84; 16]).unwrap(),
            provider
                .members
                .iter()
                .map(|retained| retained.member.clone())
                .collect(),
            state_type,
            vec![0x85],
            checkpoint.clone(),
            vec![0x86],
        )
        .expect("retained immutable admission proposal");
        let input = client
            .prepare_absent(lease, proposal)
            .expect("prepare retained input");
        Self {
            fleet,
            server,
            shutdown_client,
            client,
            provider,
            transport,
            input,
            key,
            checkpoint,
            sequence_before,
        }
    }

    async fn readback(&self) -> RecoveredRoster {
        match self
            .client
            .admission_status(&self.input)
            .await
            .expect("exact admission readback")
        {
            RecoveryOutcome::Admitted(recovered) => recovered,
            _ => panic!("the exact nonterminal admission must remain retained"),
        }
    }

    async fn reconcile_all(&self, recovered: &mut RecoveredRoster) -> Vec<MemberProof> {
        assert_eq!(recovered.members().len(), self.provider.members.len());
        let mut proofs = Vec::new();
        for ordinal in 0..u8::try_from(self.provider.members.len()).unwrap() {
            let retained = &self.provider.members[usize::from(ordinal)].member;
            assert_eq!(recovered.members()[usize::from(ordinal)], *retained);
            let mut member = recovered
                .member(MemberOrdinal::new(ordinal).unwrap())
                .unwrap();
            match self
                .client
                .reconcile(&mut member)
                .await
                .expect("reconcile exact member")
            {
                MemberRecoveryOutcome::Conclusive(proof) => proofs.push(*proof),
                MemberRecoveryOutcome::Ambiguous(_) => {}
                other => panic!("reconciliation must not restore execution: {other:?}"),
            }
        }
        proofs
    }

    async fn finish_aborted(&mut self, recovered: &RecoveredRoster, proofs: Vec<MemberProof>) {
        let proofs = CompleteProofSet::new(proofs).expect("complete SDK-issued proof set");
        let mut terminal = self
            .client
            .prepare_terminal(recovered.for_terminal(), &proofs)
            .await
            .expect("prepare exact Aborted body");
        assert!(matches!(
            self.client.terminalize(&mut terminal).await.unwrap(),
            TerminalizationOutcome::OutcomeUnknown
        ));
        match self.client.terminal_status(&mut terminal).await.unwrap() {
            TerminalStatus::Committed(TerminalReceipt::Aborted(receipt)) => {
                assert_eq!(receipt.protected_checkpoint(), self.checkpoint);
                assert_eq!(receipt.protected_result(), [0x86]);
                self.provider.release_aborted(&receipt).await;
            }
            _ => panic!("lost terminal reply must read back the exact Aborted receipt"),
        }
        self.fleet
            .wait_all_application_sequences(self.sequence_before + 2)
            .await;
        assert_eq!(
            self.transport.roster_terminal_calls.load(Ordering::SeqCst),
            1
        );
        assert_eq!(
            self.transport.roster_admission_calls.load(Ordering::SeqCst),
            1
        );
        for store in &self.fleet.stores {
            assert!(store.get(&self.key).await.unwrap().is_none());
        }
    }

    async fn shutdown(mut self) {
        self.shutdown_client.shutdown().await;
        self.server.abort_and_wait().await;
        self.fleet.quiesce().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fenced_non_execution_lost_admission_settles_every_unstarted_member() {
    let mut fixture = SettlementFixture::start(true).await;
    assert!(matches!(
        fixture.client.admit(&mut fixture.input).await.unwrap(),
        AdmissionOutcome::OutcomeUnknown(_)
    ));
    fixture
        .fleet
        .wait_all_application_sequences(fixture.sequence_before + 1)
        .await;
    assert_eq!(
        fixture
            .transport
            .roster_admission_recorded_responses
            .load(Ordering::SeqCst),
        1
    );
    let mut recovered = fixture.readback().await;
    let proofs = fixture.reconcile_all(&mut recovered).await;
    let count = proofs.len();
    let observations = fixture.provider.observations.lock().unwrap().clone();
    assert_eq!(fixture.provider.prepares.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.provider.executions.load(Ordering::SeqCst), 0);
    if count == usize::from(WIDTH) {
        fixture.finish_aborted(&recovered, proofs).await;
    }
    fixture.shutdown().await;
    assert_eq!(count, usize::from(WIDTH),
        "exact generation closure must prove every unstarted member; actual XFRM observations: {observations:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fenced_non_execution_prepared_receipt_control_reaches_exact_aborted_readback() {
    let mut fixture = SettlementFixture::start(false).await;
    let mut active = match fixture.client.admit(&mut fixture.input).await.unwrap() {
        AdmissionOutcome::Admitted(active) => active,
        _ => panic!("control admission must succeed"),
    };
    for ordinal in 0..WIDTH {
        let mut member = active.member(MemberOrdinal::new(ordinal).unwrap()).unwrap();
        assert!(matches!(
            fixture.client.prepare_member(&mut member).await.unwrap(),
            MemberPrepareOutcome::Prepared
        ));
    }
    let mut recovered = fixture.readback().await;
    let proofs = fixture.reconcile_all(&mut recovered).await;
    assert_eq!(
        proofs.len(),
        usize::from(WIDTH),
        "existing Prepared retirement is the positive receipt control"
    );
    fixture.finish_aborted(&recovered, proofs).await;
    assert_eq!(fixture.provider.executions.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}
