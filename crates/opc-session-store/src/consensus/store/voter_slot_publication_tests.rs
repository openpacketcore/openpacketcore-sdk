use super::*;
use crate::consensus::snapshot::SnapshotArtifactGate;
use crate::sqlite::consensus::wal::Point;
use futures_util::FutureExt;
use opc_consensus::engine::storage::RaftLogStorage;
use std::panic::AssertUnwindSafe;

struct ReleasePublication(Arc<SnapshotArtifactGate>);

impl Drop for ReleasePublication {
    fn drop(&mut self) {
        self.0.release();
    }
}

async fn publication_fleet() -> (Fleet, Arc<SnapshotArtifactGate>) {
    publication_fleet_on_slot(2).await
}

async fn publication_fleet_on_slot(slot: u16) -> (Fleet, Arc<SnapshotArtifactGate>) {
    let publication = Arc::new(SnapshotArtifactGate::new());
    let hook = publication.clone();
    let fleet = Fleet::open_size_with_io_hook(
        3,
        Some((
            slot,
            Arc::new(move |point| {
                if point == Point::AfterCutPublish {
                    hook.block_if_armed_blocking();
                }
                Ok(())
            }),
        )),
    )
    .await;
    (fleet, publication)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_status_waits_for_the_leaders_strict_wal_publication() {
    let (fleet, publication) = publication_fleet_on_slot(1).await;
    let result = AssertUnwindSafe(async {
        let _release = ReleasePublication(publication.clone());
        let leader = fleet.nodes[0].clone();
        let vote = leader.inner.raft.metrics().borrow().vote;
        let mut log = crate::sqlite::consensus::wal::adapter::WalLogStore::new(Arc::clone(
            leader.inner.private_wal.as_ref().unwrap(),
        ));
        publication.arm();
        // Republish the same vote through the real WAL adapter. Holding an
        // engine log append here would also block its quorum-read command.
        let write = tokio::spawn(async move { log.save_vote(&vote).await });
        tokio::time::timeout(Duration::from_secs(5), publication.wait_started())
            .await
            .expect("the leader must enter the strict publication interval");
        assert_eq!(
            leader
                .inner
                .private_wal
                .as_ref()
                .unwrap()
                .native_voter_slot_state()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        // A quorum read can finish while the leader's own durable cut is still
        // unpublished. The public status call must then wait for that cut.
        tokio::time::timeout(
            Duration::from_secs(5),
            leader.inner.raft.ensure_linearizable(),
        )
        .await
        .expect("the quorum read is independent of local publication")
        .unwrap();
        let authority = VoterReplacementAuthorization::new(
            genesis().cluster_instance,
            BTreeSet::from([SlotId::new(3).unwrap()]),
            "spiffe://example.test/recovery-controller".into(),
            public(&member(21, 1)),
            [19; 32],
            Duration::from_secs(90),
        )
        .unwrap();
        let mut status = tokio::spawn(async move {
            leader
                .voter_replacement_status(
                    &authority,
                    "spiffe://example.test/recovery-controller",
                    SlotId::new(3).unwrap(),
                    opc_consensus::ConsensusRequestId::from_bytes([0xD3; 16]),
                    [0xD3; 32],
                )
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut status)
                .await
                .is_err(),
            "status must wait for the leader's publication instead of returning Unavailable"
        );
        publication.release();
        assert!(tokio::time::timeout(Duration::from_secs(5), status)
            .await
            .expect("publication must wake the pending status read")
            .unwrap()
            .unwrap()
            .is_none());
        tokio::time::timeout(Duration::from_secs(5), write)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_status_waits_for_a_survivors_strict_wal_publication() {
    let (mut fleet, publication) = publication_fleet().await;
    let result = AssertUnwindSafe(async {
        let _release = ReleasePublication(publication.clone());
        let leader = fleet.nodes[0].clone();
        fleet
            .network
            .handlers
            .write()
            .unwrap()
            .remove(&member(3, 1).identity.node_id());
        fleet.nodes.pop().unwrap().shutdown().await.unwrap();
        tokio::time::sleep(VOTER_RECENT_TRAFFIC_WINDOW + Duration::from_millis(100)).await;
        let prepared = leader
            .replace_voter(verified_request(&genesis(), 3))
            .await
            .unwrap();
        let retained = prepared.table().replacement.as_ref().unwrap();
        fleet.nodes[1]
            .inner
            .raft
            .wait(Some(Duration::from_secs(5)))
            .applied_index_at_least(Some(retained.evidence.prepare.index), "survivor Prepare")
            .await
            .unwrap();

        publication.arm();
        let writer = leader.clone();
        let write = tokio::spawn(async move {
            writer
                .inner
                .raft
                .client_write(probe_marker(&writer, 0xD1, 1))
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), publication.wait_started())
            .await
            .expect("the follower must enter the strict publication interval");
        assert_eq!(
            fleet.nodes[1]
                .inner
                .private_wal
                .as_ref()
                .unwrap()
                .native_voter_slot_state()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        let authority = VoterReplacementAuthorization::new(
            genesis().cluster_instance,
            BTreeSet::from([SlotId::new(3).unwrap()]),
            "spiffe://example.test/recovery-controller".into(),
            public(&member(21, 1)),
            [19; 32],
            Duration::from_secs(90),
        )
        .unwrap();
        fleet
            .network
            .observe_empty_append_to
            .store(member(2, 1).identity.node_id().get(), Ordering::SeqCst);
        let request_id = retained.attestation.request_id;
        let request_digest = retained.attestation.request_digest;
        let mut status = tokio::spawn(async move {
            leader
                .voter_replacement_status(
                    &authority,
                    "spiffe://example.test/recovery-controller",
                    SlotId::new(3).unwrap(),
                    request_id,
                    request_digest,
                )
                .await
        });
        tokio::time::timeout(
            Duration::from_secs(5),
            fleet.network.empty_append_started.notified(),
        )
        .await
        .expect("a read probe must reach the follower while publication is held");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut status)
                .await
                .is_err(),
            "the read must wait for publication instead of reporting no surviving quorum"
        );
        publication.release();
        let observed = tokio::time::timeout(Duration::from_secs(5), status)
            .await
            .expect("publication must wake the pending read")
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            observed.table().replacement.as_ref().unwrap().attestation,
            retained.attestation
        );
        tokio::time::timeout(Duration::from_secs(5), write)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voter_publication_wait_honors_deadline_and_storage_failure() {
    let (fleet, publication) = publication_fleet().await;
    let result = AssertUnwindSafe(async {
        let _release = ReleasePublication(publication.clone());
        publication.arm();
        let leader = fleet.nodes[0].clone();
        let write = tokio::spawn(async move {
            leader
                .inner
                .raft
                .client_write(probe_marker(&leader, 0xD2, 1))
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), publication.wait_started())
            .await
            .unwrap();
        let wal = fleet.nodes[1].inner.private_wal.as_ref().unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            wal.with_durable_voter_slots_until(deadline, |native| native.voter_slot_state()),
        )
        .await
        .expect("waiting for publication must respect the original deadline")
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(tokio::time::Instant::now() >= deadline);
        assert_eq!(
            wal.native_voter_slot_state().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "deadline expiry must not expose unpublished voter state"
        );

        let waiting = wal.with_durable_voter_slots_until(
            tokio::time::Instant::now() + Duration::from_secs(5),
            |native| native.voter_slot_state(),
        );
        tokio::pin!(waiting);
        assert!(waiting.as_mut().now_or_never().is_none());
        wal.fence_for_test().unwrap();
        let error = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("a storage failure must wake the already pending read")
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        publication.release();
        // The two other voters still form a quorum despite the injected fault.
        tokio::time::timeout(Duration::from_secs(5), write)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    })
    .catch_unwind()
    .await;
    fleet.network.handlers.write().unwrap().clear();
    for (index, node) in fleet.nodes.into_iter().enumerate() {
        let closed = node.shutdown().await;
        if index != 1 {
            closed.unwrap();
        }
        // The deliberately fenced follower may report its injected failure.
    }
    result.unwrap();
}
