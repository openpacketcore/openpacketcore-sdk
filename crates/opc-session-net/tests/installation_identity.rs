//! Installation-qualified identity at topology admission and retained-store open.
//!
//! A fresh installation reusing the same human-readable cluster name presents
//! a distinct typed identity through `SessionReplicationManifest` and
//! `ValidatedQuorumTopology`. Linux retained-store checks also prove refusal of
//! a foreign installation preserves the original installation's reopenability.

use std::collections::BTreeSet;

use opc_session_net::{
    SessionClusterId, SessionConfigurationEpoch, SessionConfigurationGeneration,
    SessionReplicationManifest,
};
use opc_session_store::{
    QuorumReplicaDescriptor, QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint,
    ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, ValidatedQuorumTopology,
};

fn descriptor(index: u16) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        ReplicaId::new(format!("replica-{index}")).expect("replica ID"),
        ReplicaEndpoint::new(format!("replica-{index}.session.invalid"), 7443).expect("endpoint"),
        ReplicaTlsIdentity::new(format!(
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/smf/instance/{index}"
        ))
        .expect("TLS identity"),
        ReplicaFailureDomain::new(format!("zone-{index}")).expect("failure domain"),
        ReplicaBackingIdentity::new(format!("disk-{index}")).expect("backing identity"),
    )
}

fn manifest(installation_nonce: [u8; 32]) -> SessionReplicationManifest {
    SessionReplicationManifest::try_new_with_epoch(
        SessionClusterId::new("session-installation").expect("cluster ID"),
        installation_nonce,
        SessionConfigurationGeneration::new("generation-1").expect("generation"),
        SessionConfigurationEpoch::new(1).expect("epoch"),
        vec![descriptor(1), descriptor(2), descriptor(3)],
    )
    .expect("manifest")
}

fn topology(manifest: &SessionReplicationManifest) -> ValidatedQuorumTopology {
    let descriptors = vec![descriptor(1), descriptor(2), descriptor(3)];
    ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
        ReplicaId::new("replica-1").expect("replica ID"),
        descriptors,
        manifest.consensus_identity(),
    ))
    .expect("topology admission")
}

#[test]
fn reinstalled_cluster_name_yields_a_distinct_store_admission_identity() {
    let original = manifest([0x31; 32]);
    let reinstalled = manifest([0x32; 32]);

    let original_topology = topology(&original);
    let reinstalled_topology = topology(&reinstalled);

    // The identity the store persists and verifies is installation-qualified:
    // same operator name, same members, same epoch, different installation.
    assert_eq!(
        original_topology.consensus_identity(),
        Some(original.consensus_identity())
    );
    assert_eq!(
        reinstalled_topology.consensus_identity(),
        Some(reinstalled.consensus_identity())
    );
    assert_ne!(
        original_topology.consensus_identity(),
        reinstalled_topology.consensus_identity()
    );
    assert_ne!(
        original_topology
            .consensus_identity()
            .expect("admitted identity")
            .cluster_id(),
        reinstalled_topology
            .consensus_identity()
            .expect("admitted identity")
            .cluster_id()
    );
    assert_ne!(original.configuration_id(), reinstalled.configuration_id());

    // The consumer-supplied local-node map is likewise installation-qualified,
    // so an old volume's node/peer expectations cannot silently match.
    let original_nodes = original_topology
        .members()
        .iter()
        .map(|member| {
            original_topology
                .consensus_node_id(member.replica_id())
                .expect("admitted node ID")
        })
        .collect::<BTreeSet<_>>();
    let reinstalled_nodes = reinstalled_topology
        .members()
        .iter()
        .map(|member| {
            reinstalled_topology
                .consensus_node_id(member.replica_id())
                .expect("admitted node ID")
        })
        .collect::<BTreeSet<_>>();
    assert_ne!(original_nodes, reinstalled_nodes);

    // Reusing the persisted installation nonce reproduces the admission identity.
    assert_eq!(
        manifest([0x31; 32]).consensus_identity(),
        original.consensus_identity()
    );
}

#[cfg(target_os = "linux")]
mod retained {
    use super::*;
    use opc_session_store::{
        ConsensusSessionStore, ConsensusSessionStoreOpenError, SessionConsensusIdentity,
        SessionConsensusNodeId, SessionConsensusPeer, SessionConsensusPeerError,
        SessionConsensusWireRequest, SessionConsensusWireResponse, SqliteSessionBackend,
    };
    use std::{collections::BTreeMap, sync::Arc};

    #[derive(Debug)]
    struct UnavailablePeer {
        node: SessionConsensusNodeId,
        identity: SessionConsensusIdentity,
    }
    #[async_trait::async_trait]
    impl SessionConsensusPeer for UnavailablePeer {
        fn node_id(&self) -> SessionConsensusNodeId {
            self.node
        }
        fn scope_identity(&self) -> Option<SessionConsensusIdentity> {
            Some(self.identity)
        }
        async fn call(
            &self,
            _: SessionConsensusWireRequest,
        ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
            Err(SessionConsensusPeerError::Unavailable)
        }
    }

    async fn open(
        directory: &std::path::Path,
        nonce: [u8; 32],
    ) -> Result<ConsensusSessionStore, ConsensusSessionStoreOpenError> {
        let manifest = manifest(nonce);
        let topology = topology(&manifest);
        let local = topology.local_consensus_node_id().unwrap();
        let peers: BTreeMap<_, Arc<dyn SessionConsensusPeer>> = topology
            .members()
            .iter()
            .filter_map(|member| {
                let node = topology.consensus_node_id(member.replica_id()).unwrap();
                if node == local {
                    None
                } else {
                    Some((
                        node,
                        Arc::new(UnavailablePeer {
                            node,
                            identity: manifest.consensus_identity(),
                        }) as Arc<dyn SessionConsensusPeer>,
                    ))
                }
            })
            .collect();
        ConsensusSessionStore::open(
            topology,
            SqliteSessionBackend::open(directory.join("session.sqlite")).unwrap(),
            directory.join("snapshots"),
            peers,
        )
        .await
    }

    #[tokio::test]
    async fn retained_store_rejects_a_new_installation_and_still_reopens_the_original() {
        let directory = tempfile::tempdir().unwrap();
        let original = open(directory.path(), [0x31; 32])
            .await
            .expect("persist the original installation identity");
        original.shutdown().await.unwrap();
        drop(original);
        let result = open(directory.path(), [0x32; 32]).await;
        assert_eq!(
            result.err(),
            Some(ConsensusSessionStoreOpenError::DurableIdentityMismatch)
        );
        let original = open(directory.path(), [0x31; 32])
            .await
            .expect("a rejected foreign installation leaves the original reopenable");
        original.shutdown().await.unwrap();
    }
}
