//! Routing regression evidence for the capacity contract's rejection rules.
//! Native retained storage and real Openraft run behind a controlled loopback
//! transport. This does not qualify production authenticated transport.

#![cfg(target_os = "linux")]

use std::sync::atomic::AtomicUsize;

use super::*;
use crate::{
    AuditKey, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, PersistErrorKind,
    RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions,
};

const PASS: usize = 0;
const LOSE_APPLIED_THEN_REJECT: usize = 1;
const REJECT: usize = 2;

struct RejectionPeer {
    target: ConsensusNodeId,
    handler: tokio::sync::RwLock<Option<Arc<dyn ConsensusRpcHandler>>>,
    mode: AtomicUsize,
    forwarded_calls: AtomicUsize,
    applied_response_lost: AtomicBool,
}

impl fmt::Debug for RejectionPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RejectionPeer(<synthetic>)")
    }
}

#[async_trait]
impl ConsensusPeer for RejectionPeer {
    fn node_id(&self) -> ConsensusNodeId {
        self.target
    }

    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        let forwarded = request.family == ConsensusRpcFamily::ForwardMutation;
        if forwarded {
            self.forwarded_calls.fetch_add(1, Ordering::SeqCst);
            if self.mode.load(Ordering::SeqCst) == REJECT {
                return Ok(encode_service_reply(&ForwardMutationReply::Rejected(
                    ForwardMutationRejection::CommandTooLarge,
                )));
            }
        }
        let handler = self
            .handler
            .read()
            .await
            .clone()
            .ok_or(ConsensusPeerError::Unavailable)?;
        let response = handler.handle(request.sender, request).await;
        if forwarded && self.mode.load(Ordering::SeqCst) == LOSE_APPLIED_THEN_REJECT {
            let payload = response
                .result
                .as_ref()
                .expect("fault must follow a valid encoded response");
            let reply: ForwardMutationReply =
                decode_config_wire(payload).expect("decode controlled forwarding response");
            assert!(
                matches!(reply, ForwardMutationReply::Applied(ref applied) if applied.result.is_ok()),
                "fault must lose a successful applied response"
            );
            self.applied_response_lost.store(true, Ordering::SeqCst);
            self.mode.store(REJECT, Ordering::SeqCst);
            return Err(ConsensusPeerError::Unavailable);
        }
        Ok(response)
    }
}

async fn verify_forward_rejection(lose_applied_response: bool) {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            if std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true") {
                std::env::var_os("RUNNER_TEMP")
            } else {
                None
            }
        })
        .expect("explicit local or hosted scratch root is required");
    let root = tempfile::Builder::new()
        .prefix("config-capacity-routing-")
        .tempdir_in(scratch)
        .expect("private retained routing fixture")
        .keep();
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&root)
        .output()
        .expect("filesystem detector is required");
    assert!(filesystem.status.success(), "filesystem detection failed");
    let filesystem = std::str::from_utf8(&filesystem.stdout)
        .expect("filesystem detector encoding")
        .trim();
    assert!(
        !filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"),
        "disk-backed retained storage is required"
    );

    let nodes = [1, 2, 3].map(|id| ConsensusNodeId::new(id).expect("synthetic node"));
    let members = nodes.into_iter().collect::<BTreeSet<_>>();
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("synthetic-capacity-routing").expect("cluster"),
        ConfigConsensusConfigurationId::from_bytes([0xD1; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
    );
    let peers = members
        .iter()
        .map(|node| {
            (
                *node,
                Arc::new(RejectionPeer {
                    target: *node,
                    handler: tokio::sync::RwLock::new(None),
                    mode: AtomicUsize::new(PASS),
                    forwarded_calls: AtomicUsize::new(0),
                    applied_response_lost: AtomicBool::new(false),
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut stores = BTreeMap::new();
    for node in &members {
        let directory = tempfile::Builder::new()
            .prefix("member-")
            .tempdir_in(&root)
            .expect("private retained member")
            .keep();
        let topology = ConfigConsensusTopology::try_new(identity, *node, members.clone())
            .expect("three-member topology");
        let options = RetainedConfigOptions::new(
            directory.join("config.sqlite"),
            RetainedConfigBinding::new(topology.clone(), [0xD2; 32], [0xD3; 32])
                .expect("retained member binding"),
            RetainedConfigDurability::Durable {
                min_free_bytes: 128 * 1024 * 1024,
            },
            256 * 1024 * 1024,
            Duration::from_secs(10),
        )
        .expect("retained options");
        let backend = SqliteBackend::provision_config_authority(
            options,
            AuditKey::new([0xD4; 32]).expect("synthetic audit key"),
        )
        .await
        .expect("durable retained provisioning");
        let routes = peers
            .iter()
            .filter(|(remote, _)| *remote != node)
            .map(|(remote, peer)| (*remote, peer.clone() as Arc<dyn ConsensusPeer>))
            .collect();
        let store =
            ConsensusConfigStore::open(topology, backend, directory.join("snapshots"), routes)
                .await
                .expect("open member");
        *peers[node].handler.write().await = Some(store.rpc_handler());
        stores.insert(*node, store);
    }
    let [first, second, third] = nodes;
    let formation_deadline = tokio::time::Instant::now()
        .checked_add(stores[&first].inner.operation_timeout)
        .expect("original formation budget");
    let (one, two, three) = tokio::time::timeout_at(formation_deadline, async {
        tokio::join!(
            stores[&first].initialize_cluster(),
            stores[&second].initialize_cluster(),
            stores[&third].initialize_cluster(),
        )
    })
    .await
    .expect("all members initialize within the original operation budget");
    one.expect("initialize first member");
    two.expect("initialize second member");
    three.expect("initialize third member");
    // Membership admission can finish before the first election. Observe the
    // real metrics event using the same deadline; do not sample or sleep.
    let leader = stores[&first]
        .wait_for_known_leader(formation_deadline)
        .await
        .expect("elected leader within the original operation budget");
    let follower = *members
        .iter()
        .find(|node| **node != leader)
        .expect("follower");
    let control = super::tests::sized_attested_commit(128);
    let target = control.record().tx_id;
    stores[&leader]
        .append_attested_commit(control)
        .await
        .expect("encrypted positive control");
    let before = stores[&follower]
        .load_latest()
        .await
        .expect("linearizable follower control read")
        .expect("positive control head");
    assert!(!before.record.rollback_point, "unmarked positive control");
    peers[&leader].mode.store(
        if lose_applied_response {
            LOSE_APPLIED_THEN_REJECT
        } else {
            REJECT
        },
        Ordering::SeqCst,
    );
    let result = stores[&follower]
        .submit_request_inner(
            opc_consensus::ConsensusRequestId::from_bytes([0xD5; 16]),
            ConfigMutationIntent::CreateRollbackPoint {
                tx_id: target,
                label: None,
            },
        )
        .await;
    let after = stores[&follower]
        .load_latest()
        .await
        .expect("read after controlled rejection")
        .expect("retained control head");
    for store in stores.values() {
        store.shutdown().await.expect("stop routing fixture member");
    }
    for peer in peers.values() {
        *peer.handler.write().await = None;
    }
    let Err(error) = result else {
        panic!("controlled rejection must return an error");
    };
    assert!(after.record.tx_id == target, "exact original record");
    assert_eq!(after.record.rollback_point, lose_applied_response);
    assert_eq!(
        peers[&leader].applied_response_lost.load(Ordering::SeqCst),
        lose_applied_response
    );
    assert_eq!(
        peers[&leader].forwarded_calls.load(Ordering::SeqCst),
        if lose_applied_response { 2 } else { 1 },
        "exact controlled routing attempts"
    );
    if lose_applied_response {
        println!("CONFIG_CAPACITY_ROUTING committed=true response_lost=true later_rejected=true");
        assert!(
            matches!(error.kind(), PersistErrorKind::OutcomeUnknown),
            "CONFIG_CAPACITY_ROUTING_RED: later rejection erased an uncertain committed outcome"
        );
    } else {
        assert!(matches!(
            error.kind(),
            PersistErrorKind::ConstraintViolation(_)
        ));
    }
}

#[tokio::test]
async fn config_capacity_first_forward_rejection_is_definite() {
    verify_forward_rejection(false).await;
}

#[tokio::test]
async fn config_capacity_lost_response_then_rejection_preserves_unknown() {
    verify_forward_rejection(true).await;
}
