#![allow(dead_code)]

use std::sync::Arc;

use opc_session_store::{
    FencedSessionReplica, QuorumReplicaDescriptor, QuorumReplicaMember, QuorumSessionStore,
    QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId,
    ReplicaTlsIdentity, SessionStoreBackend, ValidatedQuorumTopology,
};

pub fn replica_id(index: usize) -> ReplicaId {
    ReplicaId::new(format!("test-replica-{index}")).expect("test replica ID")
}

pub fn member(index: usize, backend: Arc<dyn SessionStoreBackend>) -> QuorumReplicaMember {
    QuorumReplicaMember::new(
        QuorumReplicaDescriptor::new(
            replica_id(index),
            ReplicaEndpoint::new(format!("test-replica-{index}.invalid"), 7443)
                .expect("test endpoint"),
            ReplicaTlsIdentity::new(format!("spiffe://test/session/replica/{index}"))
                .expect("test TLS identity"),
            ReplicaFailureDomain::new(format!("test-failure-domain-{index}"))
                .expect("test failure domain"),
            ReplicaBackingIdentity::new(format!("test-backing-{index}"))
                .expect("test backing identity"),
        ),
        FencedSessionReplica::new(index, backend),
    )
}

pub fn validated_ha(members: Vec<QuorumReplicaMember>) -> QuorumSessionStore {
    let topology =
        ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new(replica_id(0), members))
            .expect("valid test HA topology");
    QuorumSessionStore::from_validated_topology(topology)
}

pub fn lab_singleton(member: QuorumReplicaMember) -> QuorumSessionStore {
    let topology = ValidatedQuorumTopology::try_new_lab_singleton(replica_id(0), vec![member])
        .expect("valid test singleton topology");
    QuorumSessionStore::from_validated_topology(topology)
}
