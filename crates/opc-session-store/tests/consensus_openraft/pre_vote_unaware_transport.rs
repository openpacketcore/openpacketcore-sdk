//! A transport that predates Pre-Vote must not lose automatic failover.
//!
//! Such a transport implements only the calls every release answers and
//! inherits the default `call_pre_vote`, which reports that a voter cannot
//! answer Pre-Vote and sends nothing. A Pre-Vote round over it can never reach
//! a quorum. Initialization elects the first leader without one, so only an
//! unplanned leader loss shows whether the survivors still elect a successor:
//! they must run the classic election instead.

use super::*;

/// A peer written before Pre-Vote existed: it forwards the calls every release
/// answers and leaves `call_pre_vote` to its default.
#[derive(Debug)]
struct PreVoteUnawarePeer(Arc<LoopbackPeer>);

#[async_trait]
impl SessionConsensusPeer for PreVoteUnawarePeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.0.node_id()
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        self.0.call(request).await
    }
}

#[tokio::test]
async fn leader_loss_elects_a_successor_over_a_transport_without_pre_vote() {
    let _timing_permit = ELECTION_AND_SNAPSHOT_TEST_PERMIT
        .acquire()
        .await
        .expect("qualification semaphore remains open");
    let cluster = TestCluster::start_with_peer_wrapper(|path| {
        let peer: Arc<dyn SessionConsensusPeer> = Arc::new(PreVoteUnawarePeer(path));
        peer
    })
    .await;
    let (leader, leader_id, term) = cluster.observed_leader();
    let survivors = (0..MEMBER_COUNT)
        .filter(|index| *index != leader)
        .collect::<Vec<_>>();

    cluster.isolate(leader);
    let lost = Instant::now();
    let elected = tokio::time::timeout(RECOVERY_TIMEOUT, async {
        loop {
            let statuses = survivors
                .iter()
                .map(|index| cluster.stores[*index].status())
                .collect::<Vec<_>>();
            if let Some(successor) = statuses[0].leader_id {
                if successor != leader_id
                    && statuses[0].term > term
                    && statuses.iter().all(|status| {
                        status.leader_id == Some(successor) && status.term == statuses[0].term
                    })
                {
                    return successor;
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await;
    let statuses = survivors
        .iter()
        .map(|index| cluster.stores[*index].status())
        .collect::<Vec<_>>();
    eprintln!(
        "leader loss over a transport without Pre-Vote: elected={} elapsed_ms={} bound_ms={}",
        elected.is_ok(),
        lost.elapsed().as_millis(),
        RECOVERY_TIMEOUT.as_millis()
    );
    let successor = elected.unwrap_or_else(|_| {
        panic!(
            "the survivors elected no successor within {}ms over a transport without \
             Pre-Vote: {statuses:?}",
            RECOVERY_TIMEOUT.as_millis()
        )
    });
    assert_ne!(successor, leader_id);

    let key = session_key(b"pre-vote-unaware-transport");
    cluster.stores[survivors[0]]
        .acquire(
            &key,
            owner("pre-vote-unaware-transport-owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("the successor commits over the transport without Pre-Vote");
}
