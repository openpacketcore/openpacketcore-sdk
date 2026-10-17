//! Full authenticated audit recovery on four Tokio workers. The paused-clock
//! sibling proves automatic election timing; this companion preserves actual
//! concurrent dispatch through every setup, commit, fencing and recovery step.

use super::election::Voters;
use super::*;

async fn elect_caught_up_survivor(quorum: &NetworkQuorum, old_leader: usize) -> usize {
    tokio::time::timeout(TRANSITION_TIMEOUT, async {
        assert_eq!(old_leader, 0);
        let old = quorum.stores[old_leader].status();
        let committed = old.committed_index.expect("committed audit prefix");
        let candidate = quorum.stores[1].status().node_id;
        let witness = quorum.stores[2].status().node_id;
        // This companion deliberately requires both followers to have already
        // applied the committed audit prefix, not merely to contain its log.
        for store in &quorum.stores[1..] {
            store
                .wait_for_raft_status_for_test(|status| {
                    status.leader_id == Some(old.node_id)
                        && status.term == old.term
                        && status.applied_index >= Some(committed)
                })
                .await
                .unwrap();
        }
        for store in &quorum.stores[1..] {
            let status = store.status();
            assert_eq!(status.term, old.term);
            assert_eq!(status.leader_id, Some(old.node_id));
            assert!(
                status.applied_index >= Some(committed),
                "applied-prefix precondition"
            );
        }
        let votes = election::VoteGate::observe(old.term + 1);
        quorum.observe_votes(Some(votes.clone()));
        // Disable outbound paths, then wait for the authenticated handlers
        // already admitted from this leader to complete. Later old-leader
        // frames cannot enter the engine, even if their caller was cancelled.
        quorum.isolate_and_quiesce(old_leader).await;
        let (one, two) = tokio::join!(
            quorum.stores[1].wait_for_vote_lease_expiry_for_test(),
            quorum.stores[2].wait_for_vote_lease_expiry_for_test(),
        );
        one.unwrap();
        two.unwrap();
        for store in &quorum.stores[1..] {
            assert_eq!(store.status().term, old.term);
        }
        // One designated campaign, with the real vote storage and mTLS
        // transport. No retry and no manufactured leadership or authority.
        quorum.stores[1].trigger_election_for_test().await.unwrap();
        let new_leader = quorum.leader_except(Some(old_leader)).await;
        assert_eq!(new_leader, 1);
        for store in &quorum.stores[1..] {
            store
                .wait_for_raft_status_for_test(|status| {
                    status.leader_id == Some(candidate) && status.term == old.term + 1
                })
                .await
                .unwrap();
        }
        votes
            .assert_one_granted_vote(candidate, witness, committed)
            .await;
        quorum.observe_votes(None);
        new_leader
    })
    .await
    .expect("synchronized election retains the original acquisition bound")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn required_running_terminal_debt_survives_authenticated_voter_leadership_change_on_four_workers(
) {
    let quorum = NetworkQuorum::open().await;
    let result = AssertUnwindSafe(async {
        assert_eq!(tokio::runtime::Handle::current().metrics().num_workers(), 4);
        // Suppress automatic campaigns before initialization, so even a
        // delayed disk or network task cannot choose a competing candidate.
        for store in &quorum.stores {
            store.disable_automatic_elections_for_test();
        }
        // Use a dedicated counter/listener around the actual config handler.
        // Background Raft traffic cannot hide a rejected call in this counter.
        // Keep admission/formation within the fleet's failure cleanup boundary.
        assert_authentication_controls(
            &quorum.pki,
            &quorum.manifest,
            quorum.stores[1].rpc_handler(),
        )
        .await;
        let (one, two, three) = tokio::join!(
            quorum.stores[0].initialize_cluster(),
            quorum.stores[1].initialize_cluster(),
            quorum.stores[2].initialize_cluster(),
        );
        one.unwrap();
        two.unwrap();
        three.unwrap();
        let old_leader = quorum.leader_except(None).await;
        assert!(quorum.stores[old_leader]
            .load_latest()
            .await
            .unwrap()
            .is_none());
        quorum.stores[old_leader]
            .initialize_audit_authority(
                &AuditPrivacyKey::new([0x81; 32]).unwrap(),
                AuditLedgerLimits::new(90, 30).unwrap(),
            )
            .await
            .unwrap();
        let old_owner = Owner::open(quorum.stores[old_leader].clone(), true).await;
        assert_eq!(quorum.checkpoints.sequence(), 3);
        let old_server = running::required_server_for_bus(old_owner.bus.clone());
        let old_sessions = SessionRegistry::new();
        let old_registration = old_sessions.register(1).unwrap();
        let request_id = RequestId::new();
        quorum.checkpoints.refuse_from.store(6, Ordering::Release);
        let reply = old_server
            .handle_rpc_for_session_async(
                request_id,
                &principal(),
                &edit("fixture-before-election"),
                &MgmtLimits::default(),
                1,
                &old_sessions,
            )
            .await;
        assert!(reply.reply_xml.contains("<ok/>"));
        let committed = old_owner
            .source
            .load_committed_latest()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(committed.version, ConfigVersion::new(2));
        assert!(
            committed.request_id == Some(request_id),
            "effect lost request"
        );
        assert_eq!(quorum.checkpoints.sequence(), 4);
        assert!(quorum.admissions.load(Ordering::Acquire) > 0);

        let new_leader = elect_caught_up_survivor(&quorum, old_leader).await;
        assert_ne!(old_leader, new_leader);
        let new_owner = Owner::open(quorum.stores[new_leader].clone(), false).await;
        let exact = new_owner
            .bus
            .resolve_request_id(request_id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            exact.tx_id == committed.tx_id,
            "election changed exact result"
        );
        assert_eq!(exact.new_version, Some(ConfigVersion::new(2)));
        let new_server = running::required_server_for_bus(new_owner.bus.clone());
        let new_sessions = SessionRegistry::new();
        let new_registration = new_sessions.register(2).unwrap();
        for (server, sessions, session_id) in [
            (&new_server, &new_sessions, 2),
            (&old_server, &old_sessions, 1),
        ] {
            let refused_request = RequestId::new();
            let refused = server
                .handle_rpc_for_session_async(
                    refused_request,
                    &principal(),
                    &edit("fixture-fenced"),
                    &MgmtLimits::default(),
                    session_id,
                    sessions,
                )
                .await;
            assert!(refused.reply_xml.contains("operation-failed"));
            assert!(new_owner
                .bus
                .resolve_request_id(refused_request)
                .await
                .unwrap()
                .is_none());
            let latest = new_owner
                .source
                .load_committed_latest()
                .await
                .unwrap()
                .unwrap();
            assert!(
                latest.tx_id == committed.tx_id,
                "fenced write changed effect"
            );
            assert_eq!(latest.version, ConfigVersion::new(2));
            assert_eq!(latest.config.hostname, "fixture-before-election");
            assert_eq!(quorum.checkpoints.sequence(), 4);
        }
        let pending = quorum.stores[new_leader]
            .reconcile_audit_obligations(30)
            .await
            .unwrap();
        assert_eq!(
            (pending.completed, pending.pending, pending.unknown),
            (0, 0, 1)
        );
        quorum.checkpoints.refuse_from.store(0, Ordering::Release);
        let settled = quorum.stores[new_leader]
            .reconcile_audit_obligations(30)
            .await
            .unwrap();
        assert_eq!(
            (settled.completed, settled.pending, settled.unknown),
            (1, 0, 0)
        );
        assert_eq!(quorum.checkpoints.sequence(), 6);
        let exact = new_owner
            .bus
            .resolve_request_id(request_id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            exact.tx_id == committed.tx_id,
            "recovery replaced original effect"
        );
        assert_eq!(exact.new_version, Some(ConfigVersion::new(2)));
        assert_original_terminal(
            quorum.stores[new_leader].as_ref(),
            quorum.identity,
            request_id,
            &committed,
        )
        .await;

        let later_request = RequestId::new();
        let permitted = new_server
            .handle_rpc_for_session_async(
                later_request,
                &principal(),
                &edit("fixture-after-election"),
                &MgmtLimits::default(),
                2,
                &new_sessions,
            )
            .await;
        assert!(permitted.reply_xml.contains("<ok/>"));
        let latest = new_owner
            .source
            .load_committed_latest()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(latest.version, ConfigVersion::new(3));
        assert_eq!(latest.config.hostname, "fixture-after-election");
        assert!(
            latest.request_id == Some(later_request),
            "later request changed"
        );
        assert!(
            latest.tx_id != committed.tx_id,
            "later write reused recovery"
        );
        assert_eq!(quorum.checkpoints.sequence(), 9);
        drop(old_registration);
        drop(new_registration);
        drop(old_server);
        drop(new_server);
        old_owner.close().await;
        new_owner.close().await;
    })
    .catch_unwind()
    .await;
    quorum.shutdown().await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
