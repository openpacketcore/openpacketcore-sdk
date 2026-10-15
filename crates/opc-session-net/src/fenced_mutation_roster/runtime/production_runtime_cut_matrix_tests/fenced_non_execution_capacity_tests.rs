//! Compose the full-store and non-admission lifecycle with the real executor,
//! signed receipts, and the namespace actor's authenticated roster store.

use super::*;
use opc_ipsec_xfrm as xfrm;

struct CapacityMember {
    member: Member,
    group: xfrm::XfrmObjectRosterGroupId,
    roster: xfrm::XfrmObjectRosterRequest,
}

struct CapacityProvider {
    actor: xfrm::NamespaceBoundLinuxXfrmBackend,
    store: xfrm::XfrmObjectRosterRecoveryStore,
    members: Vec<CapacityMember>,
    ready: Mutex<HashMap<u8, xfrm::XfrmObjectRosterAdmissionAuthority>>,
    bindings: Mutex<HashMap<u8, [u8; 32]>>,
    reconciliations: AtomicUsize,
}

impl CapacityProvider {
    fn generation() -> xfrm::XfrmObjectRosterOperationGeneration {
        xfrm::XfrmObjectRosterOperationGeneration::new(37).unwrap()
    }

    fn bind(&self, call: &MemberCall<'_>) -> &CapacityMember {
        let retained = &self.members[usize::from(call.ordinal())];
        assert_eq!(call.operation_id(), retained.member.operation_id());
        assert_eq!(call.descriptor(), retained.member.descriptor());
        assert_eq!(call.expected_version(), retained.member.expected_version());
        let binding = call.fence_binding_commitment();
        assert_eq!(
            *self
                .bindings
                .lock()
                .unwrap()
                .entry(call.ordinal())
                .or_insert(binding),
            binding
        );
        retained
    }

    async fn release(&self, receipt: &TerminalCommitReceipt) {
        for (ordinal, retained) in self.members.iter().enumerate() {
            assert_eq!(
                receipt.settled_member_binding(ordinal as u8),
                self.bindings.lock().unwrap().get(&(ordinal as u8)).copied()
            );
            self.actor
                .release_durable_object_roster_settlement(
                    &self.store,
                    retained.group,
                    Self::generation(),
                    &retained.roster,
                )
                .await
                .unwrap();
            assert!(self
                .actor
                .prepare_durable_object_roster(
                    &self.store,
                    retained.group,
                    Self::generation(),
                    retained.roster.clone(),
                )
                .await
                .is_err());
        }
    }
}

#[async_trait]
impl MemberProvider for CapacityProvider {
    type Error = ();

    async fn prepare(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        let retained = self.bind(call);
        let authority = self
            .actor
            .prepare_durable_object_roster(
                &self.store,
                retained.group,
                Self::generation(),
                retained.roster.clone(),
            )
            .await
            .map_err(|_| ())?;
        self.ready.lock().unwrap().insert(call.ordinal(), authority);
        Ok(ProviderCallOutcome::prepared_not_run())
    }

    async fn execute(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.bind(call);
        let authority = self
            .ready
            .lock()
            .unwrap()
            .remove(&call.ordinal())
            .ok_or(())?;
        let outcome = self
            .actor
            .run_durable_object_roster(authority)
            .await
            .map_err(|_| ())?;
        assert_eq!(outcome.as_str(), "applied");
        signed_provider_receipt(call, RosterProviderOutcomeV1::AppliedExecuted, vec![0xBA])
    }

    async fn status(&self, _: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        Ok(ProviderCallOutcome::outcome_unknown())
    }

    async fn adopt(&self, _: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        Ok(ProviderCallOutcome::outcome_unknown())
    }

    async fn reconcile_member(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, ()> {
        self.reconciliations.fetch_add(1, Ordering::SeqCst);
        let retained = self.bind(call);
        let outcome = self
            .actor
            .fence_durable_object_roster(
                &self.store,
                retained.group,
                Self::generation(),
                &retained.roster,
            )
            .await
            .map_err(|_| ())?;
        assert!(outcome.closed_without_effect());
        signed_provider_receipt(
            call,
            RosterProviderOutcomeV1::NotAppliedReconciled,
            vec![0xBB],
        )
    }
}

async fn capacity_case(
    actor: &xfrm::NamespaceBoundLinuxXfrmBackend,
    store: &xfrm::XfrmObjectRosterRecoveryStore,
    index: u8,
) -> (RegistrationRequest, Arc<CapacityProvider>) {
    let mut members = Vec::new();
    for ordinal in 0..2 {
        let identity_byte = index * 2 + ordinal + 1;
        let group = xfrm::XfrmObjectRosterGroupId::from_bytes([identity_byte; 16]).unwrap();
        let operation = MemberOperationId::from_bytes([identity_byte; 16]).unwrap();
        let roster =
            xfrm::XfrmObjectRosterRequest::new(vec![xfrm::XfrmObjectRosterMemberRequest::new(
                xfrm::XfrmObjectInstallRequest::Policy(xfrm::InstallPolicyRequest {
                    parameters: xfrm::PolicyParameters {
                        selector: xfrm::XfrmSelector::new(
                            xfrm::IpAddress::Ipv4([192, 0, 2, identity_byte]),
                            xfrm::IpAddress::Ipv4([198, 51, 100, identity_byte]),
                            17,
                        ),
                        direction: xfrm::XfrmDirection::Out,
                        action: xfrm::XfrmAction::Block,
                        priority: 100 + u32::from(identity_byte),
                        templates: Vec::new(),
                        mark: None,
                        if_id: None,
                    },
                }),
            )
            .with_identity(*operation.as_bytes(), CapacityProvider::generation())])
            .unwrap();
        let identity = actor
            .register_durable_object_roster_settlement(
                store,
                group,
                CapacityProvider::generation(),
                &roster,
            )
            .await
            .unwrap();
        let mut descriptor = vec![index, ordinal, identity_byte];
        descriptor.extend_from_slice(&identity.to_bytes());
        descriptor.extend_from_slice(&CapacityProvider::generation().get().to_be_bytes());
        let member = Member::new(ordinal, operation, descriptor, u64::from(identity_byte)).unwrap();
        members.push(CapacityMember {
            member,
            group,
            roster: roster.with_settlement_identity(identity),
        });
    }
    let template = request_with_members(2);
    let admission = Admission::authenticate(
        AdmissionProposal::new(
            Profile::v1(),
            RosterId::from_bytes([index + 1; 16]).unwrap(),
            members
                .iter()
                .map(|retained| retained.member.clone())
                .collect(),
            EstablishedMutation::no_op(),
            vec![0xBC],
            vec![0xBD],
            vec![0xBE],
        )
        .unwrap(),
        template.admission().key().clone(),
        template.admission().scope(),
        template.admission().logical_owner().clone(),
        FenceToken::new(1),
        Generation::new(1),
    )
    .unwrap();
    let request = RegistrationRequest::new(
        admission,
        template.admission().logical_owner().clone(),
        FenceToken::new(1),
        7,
        Generation::new(1),
    )
    .unwrap();
    (
        request,
        Arc::new(CapacityProvider {
            actor: actor.clone(),
            store: store.clone(),
            members,
            ready: Mutex::new(HashMap::new()),
            bindings: Mutex::new(HashMap::new()),
            reconciliations: AtomicUsize::new(0),
        }),
    )
}

fn capacity_store(
    root: &tempfile::TempDir,
    effects: Arc<AtomicUsize>,
) -> (
    xfrm::NamespaceBoundLinuxXfrmBackend,
    xfrm::XfrmObjectRosterRecoveryStore,
) {
    xfrm::LinuxXfrmBackend::with_instrumented_transport(move |operation, _| match operation {
        "query_policy" => Err(xfrm::XfrmError::NotFound),
        "install_policy" => {
            effects.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }
        _ => panic!("settlement must not delete or alter a kernel object"),
    })
    .bind_current_network_namespace_with_object_roster_recovery(
        root.path().join("rosters"),
        xfrm::XfrmObjectRosterRecoveryProofKey::new([0xB1; 32]).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn fenced_non_execution_thirty_width_two_admissions_settle_aborted_at_full_capacity() {
    let root = tempfile::tempdir().unwrap();
    let effects = Arc::new(AtomicUsize::new(0));
    let (actor, store) = capacity_store(&root, Arc::clone(&effects));
    let mut cases = Vec::new();
    for index in 0..30 {
        let (request, provider) = capacity_case(&actor, &store, index).await;
        let executor = RosterExecutor::new(
            Arc::clone(&provider),
            Arc::new(CutBackend::default()),
            CutAttestor::new(request.admission().scope()),
            NonZeroUsize::new(4).unwrap(),
        );
        let active = executor.register(request.clone()).await.unwrap();
        assert!(matches!(
            executor.prepare(&active, 0).await.unwrap(),
            CallResult::PreparedNotRun
        ));
        cases.push((request, provider, executor, active));
    }
    let (next_request, next_provider) = capacity_case(&actor, &store, 30).await;
    let next = &next_provider.members[0];
    assert_eq!(
        actor
            .prepare_durable_object_roster(
                &store,
                next.group,
                CapacityProvider::generation(),
                next.roster.clone()
            )
            .await
            .unwrap_err(),
        xfrm::XfrmObjectRosterDurableError::CapacityExceeded
    );
    for (request, provider, executor, active) in cases {
        let recovered = recovered(executor.admission_status(request.clone()).await.unwrap());
        // The first negative must close the absent member while all thirty
        // durable slots are still held; it cannot wait for a sibling's release.
        let absent = conclusive(executor.reconcile_member(&recovered, 1).await.unwrap());
        let prepared = conclusive(executor.reconcile_member(&recovered, 0).await.unwrap());
        let terminal = executor
            .prepare_terminal(&recovered, vec![prepared, absent])
            .await
            .unwrap();
        let receipt = executor.terminalize(&recovered, &terminal).await.unwrap();
        assert_eq!(receipt.phase(), Phase::Aborted);
        provider.release(&receipt).await;
        assert!(matches!(
            executor.admission_status(request).await.unwrap(),
            RecoveryResult::Aborted(_)
        ));
        assert!(executor.execute(&active, 0).await.is_err());
        assert_eq!(executor.backend.admission_calls().len(), 1);
        assert_eq!(executor.backend.terminal_calls().len(), 1);
    }
    let next_executor = RosterExecutor::new(
        next_provider,
        Arc::new(CutBackend::default()),
        CutAttestor::new(next_request.admission().scope()),
        NonZeroUsize::new(4).unwrap(),
    );
    let next = next_executor.register(next_request).await.unwrap();
    assert!(matches!(
        next_executor.prepare(&next, 0).await.unwrap(),
        CallResult::PreparedNotRun
    ));
    assert_eq!(effects.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn fenced_non_execution_not_transmitted_retry_registers_executes_and_releases() {
    let root = tempfile::tempdir().unwrap();
    let effects = Arc::new(AtomicUsize::new(0));
    let (actor, store) = capacity_store(&root, Arc::clone(&effects));
    let (request, provider) = capacity_case(&actor, &store, 0).await;
    let backend = Arc::new(CutBackend::default());
    backend.admission_not_transmitted_once();
    let executor = RosterExecutor::new(
        Arc::clone(&provider),
        backend,
        CutAttestor::new(request.admission().scope()),
        NonZeroUsize::new(4).unwrap(),
    );
    assert!(matches!(
        executor.register(request.clone()).await,
        Err(ExecutorError::AdmissionNotTransmitted)
    ));
    for retained in &provider.members {
        actor
            .discard_unadmitted_durable_object_roster_settlement(
                &store,
                retained.group,
                CapacityProvider::generation(),
                &retained.roster,
            )
            .await
            .unwrap();
        assert!(actor
            .prepare_durable_object_roster(
                &store,
                retained.group,
                CapacityProvider::generation(),
                retained.roster.clone()
            )
            .await
            .is_err());
        assert_eq!(
            actor
                .register_durable_object_roster_settlement(
                    &store,
                    retained.group,
                    CapacityProvider::generation(),
                    &retained.roster,
                )
                .await
                .unwrap(),
            retained.roster.settlement_identity().unwrap()
        );
    }
    let active = executor.register(request).await.unwrap();
    let mut proofs = Vec::new();
    for ordinal in 0..2 {
        assert!(matches!(
            executor.prepare(&active, ordinal).await.unwrap(),
            CallResult::PreparedNotRun
        ));
        proofs.push(conclusive(
            executor.execute(&active, ordinal).await.unwrap(),
        ));
        let retained = &provider.members[usize::from(ordinal)];
        assert_eq!(
            actor
                .finalize_durable_object_roster(
                    &store,
                    retained.group,
                    CapacityProvider::generation(),
                    &retained.roster
                )
                .await
                .unwrap(),
            xfrm::XfrmObjectRosterDurablePhase::Committed
        );
    }
    let terminal = executor.prepare_terminal(&active, proofs).await.unwrap();
    let receipt = executor.terminalize(&active, &terminal).await.unwrap();
    assert_eq!(receipt.phase(), Phase::Established);
    provider.release(&receipt).await;
    assert_eq!(effects.load(Ordering::SeqCst), 2);
    assert_eq!(executor.backend.admission_calls().len(), 2);
    assert_eq!(executor.backend.terminal_calls().len(), 1);
}

#[tokio::test]
async fn fenced_non_execution_unknown_uncommitted_admissions_discard_every_registration() {
    let root = tempfile::tempdir().unwrap();
    let effects = Arc::new(AtomicUsize::new(0));
    let (actor, store) = capacity_store(&root, Arc::clone(&effects));
    for index in 0..32 {
        let (request, provider) = capacity_case(&actor, &store, index).await;
        let backend = Arc::new(CutBackend::default());
        backend.state.lock().unwrap().next_admission_outcome_unknown = true;
        let executor = RosterExecutor::new(
            Arc::clone(&provider),
            Arc::clone(&backend),
            CutAttestor::new(request.admission().scope()),
            NonZeroUsize::new(4).unwrap(),
        );
        assert!(matches!(
            executor.register(request.clone()).await,
            Err(ExecutorError::AdmissionOutcomeUnknown)
        ));
        // Only a returned Admitted supplies execution authority. The consumer
        // discards these unbegun bindings even though commit remains unknown.
        for retained in &provider.members {
            actor
                .discard_unadmitted_durable_object_roster_settlement(
                    &store,
                    retained.group,
                    CapacityProvider::generation(),
                    &retained.roster,
                )
                .await
                .unwrap();
            assert!(actor
                .prepare_durable_object_roster(
                    &store,
                    retained.group,
                    CapacityProvider::generation(),
                    retained.roster.clone(),
                )
                .await
                .is_err());
        }
        assert!(matches!(
            executor.admission_status(request).await,
            Err(ExecutorError::AuthorityRejected)
        ));
        assert_eq!(backend.admission_calls().len(), 1);
        assert!(backend.terminal_calls().is_empty());
        assert_eq!(provider.reconciliations.load(Ordering::SeqCst), 0);
    }
    assert_eq!(effects.load(Ordering::SeqCst), 0);
}

async fn compacted_terminal_releases_full_store(status_readback: bool) {
    let root = tempfile::tempdir().unwrap();
    let effects = Arc::new(AtomicUsize::new(0));
    let (actor, store) = capacity_store(&root, Arc::clone(&effects));
    for index in 0..29 {
        let (_, provider) = capacity_case(&actor, &store, index).await;
        let retained = &provider.members[0];
        drop(
            actor
                .prepare_durable_object_roster(
                    &store,
                    retained.group,
                    CapacityProvider::generation(),
                    retained.roster.clone(),
                )
                .await
                .unwrap(),
        );
    }
    let (request, provider) = capacity_case(&actor, &store, 29).await;
    let backend = Arc::new(CutBackend::default());
    let executor = RosterExecutor::new(
        Arc::clone(&provider),
        Arc::clone(&backend),
        CutAttestor::new(request.admission().scope()),
        NonZeroUsize::new(4).unwrap(),
    );
    let active = executor.register(request.clone()).await.unwrap();
    assert!(matches!(
        executor.prepare(&active, 0).await.unwrap(),
        CallResult::PreparedNotRun
    ));
    let active = recovered(executor.admission_status(request.clone()).await.unwrap());
    let second = recovered(executor.admission_status(request).await.unwrap());
    let (next_request, next_provider) = capacity_case(&actor, &store, 30).await;
    let next = &next_provider.members[0];
    assert_eq!(
        actor
            .prepare_durable_object_roster(
                &store,
                next.group,
                CapacityProvider::generation(),
                next.roster.clone(),
            )
            .await
            .unwrap_err(),
        xfrm::XfrmObjectRosterDurableError::CapacityExceeded
    );
    let mut proofs = Vec::new();
    for ordinal in 0..2 {
        proofs.push(conclusive(
            executor.reconcile_member(&active, ordinal).await.unwrap(),
        ));
    }
    let prepared = executor.prepare_terminal(&active, proofs).await.unwrap();
    backend.compact_next_terminal();
    if status_readback {
        backend.lose_next_terminal_reply();
        assert!(matches!(
            executor.terminalize(&active, &prepared).await,
            Err(ExecutorError::TerminalizeOutcomeUnknown)
        ));
        assert!(matches!(
            executor.terminal_status(&active, &prepared).await,
            Ok(TerminalStatusResult::Compacted)
        ));
    } else {
        assert!(matches!(
            executor.terminalize(&active, &prepared).await,
            Err(ExecutorError::TerminalPayloadCompacted)
        ));
    }
    // The SDK validated the exact retained terminal body against the durable
    // tombstone. That result authorizes the trusted consumer's release even
    // when the payload receipt has aged out.
    for retained in &provider.members {
        actor
            .release_durable_object_roster_settlement(
                &store,
                retained.group,
                CapacityProvider::generation(),
                &retained.roster,
            )
            .await
            .unwrap();
    }
    let next_executor = RosterExecutor::new(
        next_provider,
        Arc::new(CutBackend::default()),
        CutAttestor::new(next_request.admission().scope()),
        NonZeroUsize::new(4).unwrap(),
    );
    let next = next_executor.register(next_request).await.unwrap();
    assert!(matches!(
        next_executor.prepare(&next, 0).await.unwrap(),
        CallResult::PreparedNotRun
    ));
    let before = provider.reconciliations.load(Ordering::SeqCst);
    let observation = executor.reconcile_member(&second, 0).await;
    assert_eq!(provider.reconciliations.load(Ordering::SeqCst), before,
        "validated compaction must refuse readback provider dispatch before released history is observed");
    assert!(observation.is_err());
    assert!(second.local.lock().unwrap().first_conclusive[0].is_none());
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert_eq!(backend.admission_calls().len(), 1);
    assert_eq!(backend.terminal_calls().len(), 1);
}

#[tokio::test]
async fn fenced_non_execution_compacted_terminalize_releases_full_store_and_revokes_readback() {
    compacted_terminal_releases_full_store(false).await;
}

#[tokio::test]
async fn fenced_non_execution_compacted_terminal_status_releases_full_store_and_revokes_readback() {
    compacted_terminal_releases_full_store(true).await;
}
