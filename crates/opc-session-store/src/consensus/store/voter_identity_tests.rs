use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_opener_reports_lost_native_root_as_identity_replacement() {
    use futures_util::FutureExt;
    use std::panic::AssertUnwindSafe;
    let mut fleet = Fleet::open().await;
    let outcome = AssertUnwindSafe(async {
        let storage_identity = fleet.nodes[0].inner.storage_identity;
        while let Some(store) = fleet.nodes.pop() {
            fleet.network.disconnect_and_shutdown(&store).await;
        }
        let directory = fleet.directories[0].path();
        let path = directory.join("session.sqlite");
        let root = directory.join("session.sqlite.native-wal");
        let key = directory.join("session.sqlite.voter-identity");
        let before = zeroize::Zeroizing::new(std::fs::read(&key).unwrap());
        std::fs::rename(&root, directory.join("lost-native-root")).unwrap();
        let backend = SqliteSessionBackend::open(&path).unwrap();
        assert_eq!(
            backend
                .native_persistence_preflight(storage_identity, |_| async { Ok(()) })
                .await,
            Err(crate::consensus::storage::SessionConsensusStorageError::CorruptState),
            "the legacy profile must retain its existing recovery refusal"
        );
        let result = ConsensusSessionStore::open_with_voter_slots_and_integrity(
            fleet.topology(1),
            fleet.genesis(),
            member(1, 1).identity.node_id(),
            backend,
            directory.join("snapshots"),
            Arc::new(Resolver(fleet.network.clone())),
            super::super::super::SnapshotIntegrityPolicy::PortableVerified,
        )
        .await;
        if let Ok(store) = &result {
            store.shutdown().await.unwrap();
        }
        assert!(matches!(result, Err(ConsensusSessionStoreOpenError::VoterIdentityReplacementRequired)), "a lost selected native root must trigger automatic incarnation replacement: {result:?}");
        assert!(!root.exists(), "refusal must not rebuild an empty native history");
        assert!(std::fs::read(key).unwrap() == *before, "refusal must preserve the retained private key");
        assert!(fleet.network.handlers.read().unwrap().is_empty());
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    outcome.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test]
async fn voter_opener_refuses_missing_or_mismatched_enrollment_before_raft() {
    for fault in 0..4 {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("session.sqlite");
        let backend = SqliteSessionBackend::open(&path).unwrap();
        let mut table = genesis();
        let local = table.slots[0].member.identity;
        if fault != 0 {
            let signer = backend
                .enroll_voter_identity(table.cluster_instance, local)
                .await
                .unwrap();
            table.slots[0].member.key_digest = signer.key_digest();
        }
        match fault {
            0 => {}
            1 => std::fs::remove_file(directory.path().join("session.sqlite.voter-identity"))
                .unwrap(),
            2 => {
                backend
                    .lock_connection_for_test()
                    .await
                    .execute(
                        "UPDATE consensus_voter_anchor SET key_digest = ?1",
                        [[0xFD; 32].as_slice()],
                    )
                    .unwrap();
            }
            3 => table.slots[0].member.key_digest[0] ^= 1,
            _ => unreachable!(),
        }
        let snapshots = directory.path().join("snapshots");
        let result = ConsensusSessionStore::open_with_voter_slots_and_integrity(
            topology_from_table(table.clone(), 1),
            table,
            local.node_id(),
            backend,
            snapshots.clone(),
            Arc::new(Resolver(Arc::new(Network::default()))),
            super::super::super::SnapshotIntegrityPolicy::PortableVerified,
        )
        .await;
        if let Ok(store) = &result {
            store.shutdown().await.unwrap();
        }
        assert!(
            matches!(
                result,
                Err(ConsensusSessionStoreOpenError::VoterIdentityReplacementRequired)
            ),
            "fault {fault} must refuse before exposing any Raft service"
        );
        assert!(
            !snapshots.exists(),
            "refusal precedes snapshot/engine initialization"
        );
        let conn = rusqlite::Connection::open(&path).unwrap();
        let consensus_identity: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'consensus_identity')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !consensus_identity,
            "refusal must not create consensus authority"
        );
    }
}

#[tokio::test]
async fn pristine_voter_refuses_unproved_and_recreated_key_traffic_before_bootstrap_grants() {
    use futures_util::FutureExt;
    use opc_consensus::engine::raft::{PreVoteRequest, PreVoteResponse};
    use opc_consensus::engine::storage::RaftLogStorage;
    use std::panic::AssertUnwindSafe;

    let fleet = Fleet::open_pristine_with_io_hook(3, None).await;
    let outcome = AssertUnwindSafe(async {
        let receiver = &fleet.nodes[1];
        let table = fleet.genesis();
        let source = table.slots[0].member.clone();
        let destination = table.slots[1].member.clone();
        let before = receiver
            .inner
            .raft
            .with_raft_state(|state| state.clone())
            .await
            .unwrap();
        let wal = receiver
            .inner
            .voter_profile
            .as_ref()
            .unwrap()
            .core
            .private_wal
            .as_ref()
            .unwrap()
            .clone();
        let mut log = crate::sqlite::consensus::wal::adapter::WalLogStore::new(wal);
        assert_eq!(log.read_vote().await.unwrap(), None);
        assert_eq!(before.membership_state, Default::default());
        assert!(!receiver.status().admitted);

        // A new volume can hold the same claimed coordinates and a real key,
        // but cannot prove the public key pinned by the published manifest.
        let rogue_directory = tempfile::tempdir().unwrap();
        let rogue_backend =
            SqliteSessionBackend::open(rogue_directory.path().join("session.sqlite")).unwrap();
        let rogue = rogue_backend
            .enroll_voter_identity(table.cluster_instance, source.identity)
            .await
            .unwrap();
        assert_ne!(rogue.key_digest(), source.key_digest);
        let mut digest = Sha256::new();
        digest.update(b"openpacketcore/session-consensus/fixed-incarnation-durable/v1\0");
        digest.update(crate::sqlite::consensus::voter_slots::COMMAND_VERSION.to_be_bytes());
        digest.update(SESSION_CONSENSUS_SCHEMA_VERSION.to_be_bytes());
        let profile_digest = digest.finalize().into();
        for family in [
            SessionConsensusRpcFamily::PreVote,
            SessionConsensusRpcFamily::Vote,
        ] {
            let payload = if family == SessionConsensusRpcFamily::PreVote {
                encode_bounded(&PreVoteRequest::new(
                    Vote::new(100, source.identity.node_id()),
                    Some(Default::default()),
                ))
                .unwrap()
            } else {
                encode_bounded(&VoteRequest {
                    vote: Vote::new(100, source.identity.node_id()),
                    last_log_id: Some(Default::default()),
                })
                .unwrap()
            };
            let request = SessionConsensusWireRequest::try_new(
                receiver.inner.storage_identity,
                source.identity.node_id(),
                family,
                payload,
            )
            .unwrap();
            let raw = receiver
                .rpc_handler()
                .handle(source.identity.node_id(), request.clone())
                .await;
            assert_eq!(raw.result, Err(SessionConsensusPeerError::ScopeMismatch));

            let binding = VoterRpcBinding {
                cluster_instance: table.cluster_instance,
                configuration: receiver.inner.storage_identity,
                profile_digest,
                source: source.clone(),
                destination: destination.clone(),
                source_spiffe_id: descriptor(1).tls_identity().as_str().into(),
                destination_spiffe_id: descriptor(2).tls_identity().as_str().into(),
                replacement_digest: None,
                payload_digest: voter_rpc_request_digest(&request).unwrap(),
                kind: VoterRpcProofKind::Request,
            };
            let issuer = VoterChallengeIssuer::new();
            let mut recreated = binding.clone();
            recreated.source.key_digest = rogue.key_digest();
            let challenge = issuer
                .issue_rpc(
                    recreated.clone(),
                    [0xDA; 32],
                    tokio::time::Instant::now() + Duration::from_secs(5),
                )
                .unwrap();
            let proof = issuer
                .verify_rpc(
                    &challenge,
                    &recreated.source_spiffe_id,
                    [0xDA; 32],
                    rogue.public_key(),
                    rogue.sign_rpc(&challenge).unwrap(),
                )
                .unwrap();
            let refused = receiver
                .rpc_handler()
                .handle_with_incarnation(proof, request.clone())
                .await;
            assert_eq!(
                refused.result,
                Err(SessionConsensusPeerError::ScopeMismatch)
            );
            assert_eq!(
                receiver
                    .inner
                    .raft
                    .with_raft_state(|state| state.clone())
                    .await
                    .unwrap(),
                before
            );
            assert_eq!(log.read_vote().await.unwrap(), None);
            assert!(!receiver.status().admitted);

            if family == SessionConsensusRpcFamily::PreVote {
                // The same complete binding and request with the retained key
                // reach the bootstrap grant, ruling out an unrelated refusal.
                let signer = fleet.network.signer(&source).unwrap();
                let challenge = issuer
                    .issue_rpc(
                        binding.clone(),
                        [0xDB; 32],
                        tokio::time::Instant::now() + Duration::from_secs(5),
                    )
                    .unwrap();
                let proof = issuer
                    .verify_rpc(
                        &challenge,
                        &binding.source_spiffe_id,
                        [0xDB; 32],
                        signer.public_key(),
                        signer.sign_rpc(&challenge).unwrap(),
                    )
                    .unwrap();
                let response = receiver
                    .rpc_handler()
                    .handle_with_incarnation(proof, request)
                    .await;
                let result: Result<
                    PreVoteResponse<SessionConsensusNodeId>,
                    RaftError<SessionConsensusNodeId>,
                > = decode_bounded(&response.result.unwrap()).unwrap();
                assert!(result.unwrap().vote_granted);
                assert_eq!(
                    receiver
                        .inner
                        .raft
                        .with_raft_state(|state| state.clone())
                        .await
                        .unwrap(),
                    before
                );
                assert_eq!(log.read_vote().await.unwrap(), None);
            }
        }
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
