use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_v2_verified_missing_excludes_delayed_original_admission_after_full_restart() {
    let pki = Arc::new(TestPki::new());
    let mut fleet = ThreeVoterConsumerFleet::start_fixed_durable_with_v2_roster_attestation(
        Arc::clone(&pki),
        ProductionRosterAttestationIssuer::trust_root(),
    )
    .await;
    let key = test_key();
    let roster_id = RosterId::from_bytes([0x91; 16]).unwrap();
    let client_spiffe = spiffe("successor-fenced-missing-client");
    let mut recovery = None;
    let mut observed = Vec::new();
    for reopened in [false, true] {
        let (leader, _, _) = fleet.wait_for_observed_leader().await;
        let server_spiffe = three_voter_spiffe(leader);
        let authorizer = three_voter_authorizer(&fleet.stores[leader], &client_spiffe).await;
        let authority = fleet.voter_authority(leader);
        let attestor = ProductionRosterAttestationIssuer::new(
            fleet.consensus_identity(leader),
            authorizer.scope(),
        );
        let ingress_signer: Arc<dyn RosterIngressSigner> = attestor.clone();
        let executor_attestor: Arc<dyn FencedMutationRosterExecutorAttestor> = attestor.clone();
        let service = Arc::new(fleet.stores[leader].consumer_service());
        let consumer: Arc<dyn SessionQuorumConsumer> = service.clone();
        let ingress: Arc<dyn SessionQuorumRosterIngress> = service;
        let delay = Arc::new(SuccessorFenceAdmissionDelay::default());
        let mut transport = CommitThenLoseConsumerResponse::roster_passthrough(consumer, ingress);
        transport.admission_delay = Some(Arc::clone(&delay));
        let transport = Arc::new(transport);
        let (server, address) = SessionQuorumConsumerServer::new(
            transport.clone(),
            pki.server_config(&server_spiffe),
            authorizer,
        )
        .with_roster_v2_ingress(transport.clone(), ingress_signer)
        .listen("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
        let persistent = protected_roster_v2_persistent_client(
            &pki,
            address,
            &server_spiffe,
            &client_spiffe,
            authority.clone(),
        );
        let shutdown = persistent.clone();
        let provider = Arc::new(
            SixMemberRosterEvidenceProvider::execute_outcome_unknown_then_reconciled(attestor),
        );
        let publication = Arc::new(EstablishedPublicationEvidenceProvider::default());
        let adapter = persistent
            .into_fenced_mutation_roster_v2_provider_adapter(
                Arc::clone(&provider),
                Arc::clone(&publication),
                executor_attestor,
                NonZeroUsize::new(THREE_VOTER_COUNT).unwrap(),
            )
            .unwrap();
        let client = adapter.client().clone();
        if !reopened {
            let leases = consumer_client(&pki, address, &server_spiffe, &client_spiffe, authority);
            let original = leases
                .acquire_with_id(
                    SessionConsumerRequestId::from_bytes([0x92; 16]),
                    key.clone(),
                    OwnerId::new("missing-original").unwrap(),
                    Duration::from_secs(60),
                )
                .await
                .unwrap();
            let proposal = AbsentAdmissionProposal::new(
                FencedMutationRosterProfile::v2(),
                roster_id,
                vec![Member::new(
                    0,
                    MemberOperationId::from_bytes([0x93; 16]).unwrap(),
                    vec![1],
                    1,
                )
                .unwrap()],
                StateType::from_static("missing-created"),
                vec![2],
                vec![3],
                vec![4],
            )
            .unwrap();
            let mut input = client.prepare_absent(original.clone(), proposal).unwrap();
            let delayed_client = client.clone();
            let delayed = tokio::spawn(async move {
                let result = delayed_client.admit(&mut input).await;
                (input, result)
            });
            tokio::time::timeout(Duration::from_secs(5), delay.entered.notified())
                .await
                .expect("the original command crossed authenticated ingress before takeover");
            leases
                .release_with_id(
                    SessionConsumerRequestId::from_bytes([0x94; 16]),
                    original.clone(),
                )
                .await
                .unwrap();
            let successor = leases
                .acquire_with_id(
                    SessionConsumerRequestId::from_bytes([0x95; 16]),
                    key.clone(),
                    OwnerId::new("missing-successor").unwrap(),
                    Duration::from_secs(60),
                )
                .await
                .unwrap();
            assert!(successor.fence() > original.fence());
            let current = AbsentRecoveryInput::new(
                roster_id,
                key.clone(),
                original.owner().clone(),
                original.fence(),
                successor,
            )
            .unwrap();
            let before = client.recover_absent(&current).await;
            observed.push(matches!(
                before,
                Err(RosterClientError::AdmissionRecordMissing)
            ));
            delay.release.notify_one();
            tokio::time::timeout(Duration::from_secs(5), delay.completed.notified())
                .await
                .expect("the delayed original command reaches its durable authority check");
            assert!(
                delay.rejected.load(Ordering::SeqCst),
                "the committed successor excludes the delayed original command"
            );
            let (_, delayed_result) = delayed.await.unwrap();
            assert!(matches!(
                delayed_result,
                Err(RosterClientError::AuthorityRejected) | Ok(AdmissionOutcome::OutcomeUnknown(_))
            ));
            assert_eq!(transport.roster_admission_calls.load(Ordering::SeqCst), 1);
            recovery = Some(current);
        }
        let current = recovery.as_ref().unwrap();
        let sequence = fleet
            .application_sequences()
            .await
            .into_iter()
            .max()
            .unwrap();
        fleet.wait_all_application_sequences(sequence).await;
        let result = client.recover_absent(current).await;
        observed.push(matches!(
            result,
            Err(RosterClientError::AdmissionRecordMissing)
        ));
        assert_eq!(
            fleet.application_sequences().await,
            [sequence; THREE_VOTER_COUNT]
        );
        for store in &fleet.stores {
            assert!(store.get(&key).await.unwrap().is_none());
        }
        assert_eq!(provider.prepare_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider.execute_calls.load(Ordering::SeqCst), 0);
        assert_eq!(publication.publish_calls.load(Ordering::SeqCst), 0);
        shutdown.shutdown().await;
        server.abort_and_wait().await;
        // The wrapper owns the old consumer service and its storage handle.
        // Release that owner before the fleet reopens the same durable files.
        drop(transport);
        if !reopened {
            fleet = fleet.restart_all().await;
        }
    }
    fleet.quiesce().await;
    assert_eq!(observed, [true, true, true], "verified successor-fenced missing must reach the public client before and after the delayed command and full restart");
}
