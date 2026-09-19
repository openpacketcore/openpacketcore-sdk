//! A real /3 admission and prepared provider intent retained across the same
//! process-loss recovery. All effects share the recovery owner's disk journal.
use super::*;
use opc_session_net::{
    FencedMutationRosterCompleteProofSet, FencedMutationRosterExecuteOutcome,
    FencedMutationRosterMemberOrdinal, FencedMutationRosterMemberPrepareOutcome,
    FencedMutationRosterMemberRecoveryOutcome, FencedMutationRosterReadyMember,
    FencedMutationRosterRecoveryOutcome, FencedMutationRosterTerminal,
    FencedMutationRosterTerminalReceipt, FencedMutationRosterTerminalizationOutcome,
};
use opc_session_store::fenced_mutation_roster::RosterProviderOutcomeV1;
use opc_session_testkit::qualification::protected_recovery::Journal;

struct Provider {
    journal: Arc<Journal>,
    scope: SessionConsumerScope,
}
impl Provider {
    fn receipt(
        &self,
        call: &FencedMutationRosterMemberCall<'_>,
        outcome: RosterProviderOutcomeV1,
    ) -> Result<FencedMutationRosterProviderCallOutcome, ()> {
        let root_key = SigningKey::from_bytes((&[0x31; 32]).into()).map_err(|_| ())?;
        let key = SigningKey::from_bytes((&[0x41; 32]).into()).map_err(|_| ())?;
        let root = qualification_roster_attestation_trust_root();
        let now = Timestamp::now_utc();
        let mut certificate = RosterAttestationLeafCertificatePartsV1 {
            root_id: root.root_id(),
            role: RosterAttestationCertificateRoleV1::Provider,
            configuration_identity: self.scope.consensus_identity(),
            scope: opc_session_store::consumer::session_consumer_roster_scope_commitment(
                self.scope,
            ),
            subject_identity_commitment: [0x91; 32],
            leaf_epoch: 1,
            key_id: [0x92; 32],
            not_before: now.add_seconds(-60).ok_or(())?,
            not_after: now.add_seconds(3_600).ok_or(())?,
            public_key: key
                .verifying_key()
                .to_sec1_point(true)
                .as_bytes()
                .try_into()
                .map_err(|_| ())?,
            root_signature: [0; 64],
        };
        certificate.root_signature = QualificationRosterIssuer::sign(
            &root_key,
            RosterAttestationLeafCertificateV1::signing_digest(&certificate).map_err(|_| ())?,
        );
        let challenge = call.provider_receipt_challenge();
        let evidence = vec![0x93];
        let digest = challenge
            .protected_provider_leaf_receipt_digest(
                certificate.subject_identity_commitment,
                outcome,
                &evidence,
            )
            .map_err(|_| ())?;
        let capsule = challenge
            .protected_provider_leaf_signed_capsule(
                outcome,
                evidence,
                certificate,
                QualificationRosterIssuer::sign(&key, digest),
            )
            .map_err(|_| ())?;
        Ok(FencedMutationRosterProviderCallOutcome::conclusive_receipt(
            capsule,
        ))
    }
}
#[async_trait::async_trait]
impl FencedMutationRosterMemberProvider for Provider {
    type Error = ();
    async fn prepare(
        &self,
        call: &FencedMutationRosterMemberCall<'_>,
    ) -> Result<FencedMutationRosterProviderCallOutcome, ()> {
        call.validate_current_lease_at(Timestamp::now_utc())
            .map_err(|_| ())?;
        self.journal
            .effect_binding(
                call.fence_binding_commitment(),
                call.current_fence().get(),
                false,
            )
            .map_err(|_| ())?;
        Ok(FencedMutationRosterProviderCallOutcome::prepared_not_run())
    }
    async fn execute(
        &self,
        call: &FencedMutationRosterMemberCall<'_>,
    ) -> Result<FencedMutationRosterProviderCallOutcome, ()> {
        call.validate_current_lease_at(Timestamp::now_utc())
            .map_err(|_| ())?;
        self.journal
            .effect_binding(
                call.fence_binding_commitment(),
                call.current_fence().get(),
                true,
            )
            .map_err(|_| ())?;
        self.receipt(call, RosterProviderOutcomeV1::AppliedExecuted)
    }
    async fn status(
        &self,
        call: &FencedMutationRosterMemberCall<'_>,
    ) -> Result<FencedMutationRosterProviderCallOutcome, ()> {
        call.validate_current_lease_at(Timestamp::now_utc())
            .map_err(|_| ())?;
        match self
            .journal
            .status_binding(call.fence_binding_commitment(), call.current_fence().get())
            .map_err(|_| ())?
        {
            Some(true) => self.receipt(call, RosterProviderOutcomeV1::AppliedExecuted),
            Some(false) => self.receipt(call, RosterProviderOutcomeV1::NotAppliedReconciled),
            None => Ok(FencedMutationRosterProviderCallOutcome::not_found()),
        }
    }
    async fn adopt(
        &self,
        call: &FencedMutationRosterMemberCall<'_>,
    ) -> Result<FencedMutationRosterProviderCallOutcome, ()> {
        call.validate_current_lease_at(Timestamp::now_utc())
            .map_err(|_| ())?;
        match self
            .journal
            .status_binding(call.fence_binding_commitment(), call.current_fence().get())
            .map_err(|_| ())?
        {
            Some(true) => self.receipt(call, RosterProviderOutcomeV1::AppliedAdopted),
            Some(false) => self.receipt(call, RosterProviderOutcomeV1::NotAppliedReconciled),
            None => Ok(FencedMutationRosterProviderCallOutcome::not_found()),
        }
    }
}

fn clients(
    fleet: &mut Fleet,
    voter: usize,
) -> (
    watch::Sender<Option<IdentityState>>,
    SessionConsumerScope,
    QualificationConsumerClient,
    PersistentSessionConsumerClient,
) {
    let identity = stateless_consumer_identity(0);
    let (endpoint, scope) =
        fleet.start_stateless_consumer(voter, (0..12).map(stateless_consumer_identity).collect());
    let (identity_source, receiver) =
        watch::channel(Some(fleet.pki.consumer_identity_state(&identity)));
    let tls = TlsConfigBuilder::new(receiver)
        .allow_any_trusted_peer()
        .build_authenticated_client_config()
        .expect("protected recovery mTLS client");
    let stateless = StatelessSessionConsumerClient::new(
        endpoint,
        rustls_pki_types::ServerName::IpAddress(endpoint.ip().into()),
        fleet.stateless_consumer_voter_authorities()[voter].clone(),
        tls,
    );
    let general = QualificationConsumerClient::Stateless(Box::new(stateless.clone()));
    let protected = PersistentSessionConsumerClient::try_from_fenced_mutation_roster_stateless(
        stateless,
        qualification_single_lane_persistent_config(),
    )
    .expect("real protected transport");
    (identity_source, scope, general, protected)
}

pub(super) struct Prepared {
    runtime: tokio::runtime::Runtime,
    run: QualificationProtectedRosterRun,
    ready: Vec<FencedMutationRosterReadyMember>,
    identity: watch::Sender<Option<IdentityState>>,
    scope: SessionConsumerScope,
    provider: Arc<Provider>,
}
impl Prepared {
    pub(super) fn start(fleet: &mut Fleet, voter: usize, journal: Arc<Journal>) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("protected recovery driver");
        let (identity, scope, general, transport) = clients(fleet, voter);
        let provider = Arc::new(Provider { journal, scope });
        let (run, ready) = runtime.block_on(async {
            transport
                .prewarm()
                .await
                .expect("protected recovery authenticated setup");
            let client = transport
                .clone()
                .into_fenced_mutation_roster_client(
                    provider.clone(),
                    QualificationRosterIssuer::new(scope),
                    NonZeroUsize::new(6).unwrap(),
                )
                .expect("fixed actual provider owner");
            let mut run = QualificationProtectedRosterRun::prepare_with_client(
                3, &general, transport, voter, scope, client,
            )
            .await;
            let mut active = match run
                .client
                .admit(&mut run.admission)
                .await
                .expect("actual committed Q1")
            {
                FencedMutationRosterAdmissionOutcome::Admitted(active) => active,
                _ => panic!("Q1 must be directly acknowledged before process loss"),
            };
            let mut ready = Vec::new();
            for ordinal in 0..6 {
                let mut member = active
                    .member(FencedMutationRosterMemberOrdinal::new(ordinal).unwrap())
                    .unwrap();
                assert!(matches!(
                    run.client.prepare_member(&mut member).await.unwrap(),
                    FencedMutationRosterMemberPrepareOutcome::Prepared
                ));
                ready.push(member);
            }
            (run, ready)
        });
        Self {
            runtime,
            run,
            ready,
            identity,
            scope,
            provider,
        }
    }

    pub(super) fn execute_one(&mut self) {
        self.runtime.block_on(async {
            assert!(matches!(
                self.run.client.execute(&mut self.ready[0]).await.unwrap(),
                FencedMutationRosterExecuteOutcome::Conclusive(_)
            ));
        });
    }

    pub(super) fn recover(mut self, fleet: &mut Fleet, returned_voter: usize, lost_q1: bool) {
        let (identity, scope, general, transport) = clients(fleet, returned_voter);
        self.runtime.block_on(async {
            assert!(scope == self.scope);
            transport
                .prewarm()
                .await
                .expect("successor protected setup");
            let old_transport = std::mem::replace(&mut self.run.transport, transport.clone());
            // Retain the old client and its prepared capabilities for the
            // delayed execute. It uses the same independent provider journal.
            let current = transport
                .into_fenced_mutation_roster_client(
                    self.provider.clone(),
                    QualificationRosterIssuer::new(scope),
                    NonZeroUsize::new(6).unwrap(),
                )
                .unwrap();
            self.identity = identity;
            old_transport.shutdown().await;
            let successor = general
                .acquire_with_id(
                    SessionConsumerRequestId::from_bytes([0x88; 16]),
                    self.run.lease.key().clone(),
                    OwnerId::new("protected-recovery-successor").unwrap(),
                    PROTECTED_ROSTER_LEASE_TTL,
                )
                .await
                .expect("actual higher-fence protected authority");
            assert!(successor.fence() > self.run.lease.fence());
            let input = self
                .run
                .admission
                .recovery(successor, Generation::new(1))
                .unwrap();
            if lost_q1 {
                // The authoritative lookup deliberately keeps missing Q1
                // ambiguous: its absence is not proof that no effect applied.
                assert_eq!(
                    current.recover(&input).await.err(),
                    Some(opc_session_net::FencedMutationRosterClientError::RecoveryRequired),
                    "lost Q1 requires recovery without inventing its admission or outcome"
                );
                for member in &mut self.ready[1..] {
                    assert!(matches!(
                        self.run.client.execute(member).await,
                        Ok(FencedMutationRosterExecuteOutcome::Ambiguous(_))
                    ));
                }
                assert_eq!(
                    self.provider.journal.progress().unwrap().1,
                    3,
                    "retirement preserves the completed effect and blocks delayed old effects"
                );
                self.run.transport.shutdown().await;
                return;
            }
            let mut recovered = match current.recover(&input).await.expect("retained exact Q1") {
                FencedMutationRosterRecoveryOutcome::Admitted(roster) => roster,
                _ => panic!("recovery preserves admitted phase"),
            };
            assert_eq!(recovered.protected_plan(), &[0x74]);
            let mut proofs = Vec::new();
            for ordinal in 0..6 {
                let mut member = recovered
                    .member(FencedMutationRosterMemberOrdinal::new(ordinal).unwrap())
                    .unwrap();
                match current
                    .status(&mut member)
                    .await
                    .expect("retired exact prepared intent")
                {
                    FencedMutationRosterMemberRecoveryOutcome::Conclusive(proof) => {
                        proofs.push(*proof)
                    }
                    _ => panic!("durably retired intent requires exact negative evidence"),
                }
            }
            let proofs = FencedMutationRosterCompleteProofSet::new(proofs).unwrap();
            let mut terminal = current
                .prepare_terminal(FencedMutationRosterTerminal::Recovered(&recovered), &proofs)
                .await
                .unwrap();
            match current
                .terminalize(&mut terminal)
                .await
                .expect("next valid protected operation")
            {
                FencedMutationRosterTerminalizationOutcome::Committed(
                    FencedMutationRosterTerminalReceipt::Aborted(receipt),
                ) => {
                    assert_eq!(receipt.protected_checkpoint(), &[0x75]);
                    assert_eq!(receipt.protected_result(), &[0x76]);
                }
                _ => panic!("only exact retired member evidence permits Aborted"),
            }
            for member in &mut self.ready {
                assert!(matches!(
                    self.run.client.execute(member).await,
                    Ok(FencedMutationRosterExecuteOutcome::Ambiguous(_))
                ));
            }
            assert_eq!(
                self.provider.journal.progress().unwrap().1,
                2,
                "old member handles cannot mutate successor"
            );
            self.run.transport.shutdown().await;
        });
    }
}
