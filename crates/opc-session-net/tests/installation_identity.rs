//! Installation-qualified identity at the topology-admission boundary.
//!
//! The retained-store/open path consumes `SessionReplicationManifest`'s
//! consensus identity through `ValidatedQuorumTopology`. A fresh installation
//! reusing the same human-readable cluster name therefore presents a different
//! typed store identity; the store's identity-mismatch refusal itself is
//! exercised by the existing `opc-session-store` retained-reopen lanes (Linux).

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
