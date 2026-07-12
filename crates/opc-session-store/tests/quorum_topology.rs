use opc_consensus::{
    derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
};
use opc_session_store::{
    QuorumReplicaDescriptor, QuorumTopologyConfig, QuorumTopologyError, QuorumTopologyMode,
    ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity,
    ReplicaTopologyField, ReplicaTopologyFieldError, SessionStorePlatformProfile,
    ValidatedQuorumTopology, QUORUM_TOPOLOGY_MAX_MEMBERS,
};
use proptest::prelude::*;

fn replica_id(index: usize) -> ReplicaId {
    ReplicaId::new(format!("replica-{index}")).expect("test replica ID")
}

fn descriptor(
    id: ReplicaId,
    endpoint_index: usize,
    tls_index: usize,
    failure_index: usize,
    backing_index: usize,
) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        id,
        ReplicaEndpoint::new(format!("replica-{endpoint_index}.test.invalid"), 7443)
            .expect("test endpoint"),
        ReplicaTlsIdentity::new(format!("spiffe://test/session/replica/{tls_index}"))
            .expect("test TLS identity"),
        ReplicaFailureDomain::new(format!("test-failure-domain-{failure_index}"))
            .expect("test failure domain"),
        ReplicaBackingIdentity::new(format!("test-backing-{backing_index}"))
            .expect("test backing identity"),
    )
}

fn member(index: usize) -> QuorumReplicaDescriptor {
    descriptor(replica_id(index), index, index, index, index)
}

fn members(count: usize) -> Vec<QuorumReplicaDescriptor> {
    (0..count).map(member).collect()
}

fn validate_ha(
    local_replica_id: ReplicaId,
    members: Vec<QuorumReplicaDescriptor>,
) -> Result<ValidatedQuorumTopology, QuorumTopologyError> {
    let identity = consensus_identity(&members);
    ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
        local_replica_id,
        members,
        identity,
    ))
}

fn consensus_identity(members: &[QuorumReplicaDescriptor]) -> ConsensusIdentity {
    let cluster_id = ConsensusClusterId::new("session-store-topology-tests").expect("cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(1).expect("configuration epoch");
    let fingerprints = members
        .iter()
        .map(QuorumReplicaDescriptor::configuration_fingerprint)
        .collect::<Vec<_>>();
    let configuration_id = derive_configuration_id(cluster_id, epoch, &fingerprints);
    ConsensusIdentity::new(cluster_id, configuration_id, epoch)
}

fn test_descriptors() -> Vec<QuorumReplicaDescriptor> {
    (0..3)
        .map(|index| descriptor(replica_id(index), index, index, index, index))
        .collect()
}

#[test]
fn validated_ha_accepts_exactly_odd_memberships_of_at_least_three() {
    for count in 0..=(QUORUM_TOPOLOGY_MAX_MEMBERS + 2) {
        let result = validate_ha(replica_id(0), members(count));
        if count > QUORUM_TOPOLOGY_MAX_MEMBERS {
            assert_eq!(
                result.err(),
                Some(QuorumTopologyError::MemberCountTooLarge {
                    configured: count,
                    max: QUORUM_TOPOLOGY_MAX_MEMBERS,
                })
            );
        } else if count >= 3 && !count.is_multiple_of(2) {
            let topology = result.expect("odd HA membership of at least three");
            assert_eq!(topology.summary().configured_members(), count);
            assert_eq!(topology.summary().required_quorum(), (count / 2) + 1);
            assert_eq!(topology.summary().mode(), QuorumTopologyMode::ValidatedHa);
        } else if count < 3 {
            assert_eq!(
                result.err(),
                Some(QuorumTopologyError::HaMemberCountTooSmall { configured: count })
            );
        } else {
            assert_eq!(
                result.err(),
                Some(QuorumTopologyError::HaMemberCountMustBeOdd { configured: count })
            );
        }
    }
}

#[test]
fn descriptor_configuration_fingerprint_is_fixed_deterministic_and_covers_every_field() {
    let base = descriptor(replica_id(0), 0, 0, 0, 0);
    let canonical_equivalent = QuorumReplicaDescriptor::new(
        replica_id(0),
        ReplicaEndpoint::new("REPLICA-0.TEST.INVALID.", 7443).expect("canonical endpoint"),
        ReplicaTlsIdentity::new("spiffe://test/session/replica/0").expect("TLS identity"),
        ReplicaFailureDomain::new("test-failure-domain-0").expect("failure domain"),
        ReplicaBackingIdentity::new("test-backing-0").expect("backing identity"),
    );
    let variants = [
        descriptor(replica_id(9), 0, 0, 0, 0),
        descriptor(replica_id(0), 9, 0, 0, 0),
        QuorumReplicaDescriptor::new(
            replica_id(0),
            ReplicaEndpoint::new("replica-0.test.invalid", 7444).expect("different port"),
            ReplicaTlsIdentity::new("spiffe://test/session/replica/0").expect("TLS identity"),
            ReplicaFailureDomain::new("test-failure-domain-0").expect("failure domain"),
            ReplicaBackingIdentity::new("test-backing-0").expect("backing identity"),
        ),
        descriptor(replica_id(0), 0, 9, 0, 0),
        descriptor(replica_id(0), 0, 0, 9, 0),
        descriptor(replica_id(0), 0, 0, 0, 9),
    ];

    let fingerprint: [u8; 32] = base.configuration_fingerprint();
    assert_eq!(fingerprint, base.configuration_fingerprint());
    assert_eq!(
        fingerprint,
        canonical_equivalent.configuration_fingerprint()
    );
    for variant in variants {
        assert_ne!(
            fingerprint,
            variant.configuration_fingerprint(),
            "every descriptor field must affect the fingerprint"
        );
    }
}

#[test]
fn three_node_consensus_topology_needs_only_member_descriptors() {
    let descriptors = test_descriptors();
    let local = descriptors[0].replica_id().clone();

    let topology = validate_ha(local, descriptors.clone())
        .expect("descriptor-only production topology must pass admission");

    assert_eq!(topology.members(), descriptors.as_slice());
    assert_eq!(topology.summary().configured_members(), 3);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn validated_ha_properties_are_order_independent(
        count in 3usize..=QUORUM_TOPOLOGY_MAX_MEMBERS,
        local_seed in any::<usize>(),
        rotation_seed in any::<usize>(),
        reverse in any::<bool>(),
    ) {
        prop_assume!(!count.is_multiple_of(2));
        let local_index = local_seed % count;
        let local_id = replica_id(local_index);
        let mut configured = members(count);
        let rotation = rotation_seed % count;
        configured.rotate_left(rotation);
        if reverse {
            configured.reverse();
        }

        let topology = validate_ha(local_id.clone(), configured)?;
        prop_assert_eq!(topology.summary().configured_members(), count);
        prop_assert_eq!(topology.summary().required_quorum(), (count / 2) + 1);
        prop_assert_eq!(topology.summary().local_replica_id(), Some(&local_id));
        prop_assert_eq!(
            topology.platform_profile(),
            SessionStorePlatformProfile::Quorum
        );
    }
}

#[test]
fn logical_self_is_exact_and_independent_from_fqdn_endpoint() {
    let bare_self = ReplicaId::new("epdg-app-0").expect("bare logical self");
    let local = QuorumReplicaDescriptor::new(
        bare_self.clone(),
        ReplicaEndpoint::new(
            "epdg-app-0.epdg-app-quorum.epdg-gateway.svc.cluster.local",
            7443,
        )
        .expect("local FQDN endpoint"),
        ReplicaTlsIdentity::new("spiffe://cluster/epdg/replica/0").expect("local TLS identity"),
        ReplicaFailureDomain::new("pod/epdg-app-0").expect("local failure domain"),
        ReplicaBackingIdentity::new("pvc/session-store-0").expect("local backing"),
    );
    let topology = validate_ha(bare_self.clone(), vec![member(1), local, member(2)])
        .expect("bare self maps by logical ID only");

    assert_eq!(
        topology.summary().local_replica_id().map(ReplicaId::as_str),
        Some("epdg-app-0")
    );
    let local_member = topology
        .members()
        .iter()
        .find(|descriptor| descriptor.replica_id() == &bare_self)
        .expect("validated local member");
    assert_eq!(
        local_member.endpoint().host(),
        "epdg-app-0.epdg-app-quorum.epdg-gateway.svc.cluster.local"
    );
}

#[test]
fn missing_and_ambiguous_local_members_fail_with_distinct_errors() {
    assert_eq!(
        validate_ha(ReplicaId::new("missing").expect("missing ID"), members(3)).err(),
        Some(QuorumTopologyError::MissingLocalReplica)
    );

    let local = replica_id(0);
    let ambiguous = vec![member(0), descriptor(local.clone(), 1, 1, 1, 1), member(2)];
    assert_eq!(
        validate_ha(local, ambiguous).err(),
        Some(QuorumTopologyError::AmbiguousLocalReplica { matches: 2 })
    );
}

#[test]
fn every_vote_identity_dimension_must_be_distinct() {
    let cases = [
        (
            vec![member(0), member(1), descriptor(replica_id(1), 2, 2, 2, 2)],
            QuorumTopologyError::DuplicateReplicaId,
        ),
        (
            vec![member(0), member(1), descriptor(replica_id(2), 1, 2, 2, 2)],
            QuorumTopologyError::DuplicateEndpoint,
        ),
        (
            vec![member(0), member(1), descriptor(replica_id(2), 2, 1, 2, 2)],
            QuorumTopologyError::DuplicateTlsIdentity,
        ),
        (
            vec![member(0), member(1), descriptor(replica_id(2), 2, 2, 1, 2)],
            QuorumTopologyError::DuplicateFailureDomain,
        ),
        (
            vec![member(0), member(1), descriptor(replica_id(2), 2, 2, 2, 1)],
            QuorumTopologyError::DuplicateBackingIdentity,
        ),
    ];

    for (members, expected) in cases {
        assert_eq!(validate_ha(replica_id(0), members).err(), Some(expected));
    }
}

#[test]
fn dns_case_and_trailing_dot_cannot_alias_two_endpoint_votes() {
    let first = QuorumReplicaDescriptor::new(
        replica_id(1),
        ReplicaEndpoint::new("PEER.SESSIONS.TEST.INVALID.", 7443)
            .expect("absolute uppercase endpoint"),
        ReplicaTlsIdentity::new("spiffe://test/session/replica/1").expect("TLS identity"),
        ReplicaFailureDomain::new("test-failure-domain-1").expect("failure domain"),
        ReplicaBackingIdentity::new("test-backing-1").expect("backing identity"),
    );
    let alias = QuorumReplicaDescriptor::new(
        replica_id(2),
        ReplicaEndpoint::new("peer.sessions.test.invalid", 7443).expect("lowercase endpoint"),
        ReplicaTlsIdentity::new("spiffe://test/session/replica/2").expect("TLS identity"),
        ReplicaFailureDomain::new("test-failure-domain-2").expect("failure domain"),
        ReplicaBackingIdentity::new("test-backing-2").expect("backing identity"),
    );

    assert_eq!(
        validate_ha(replica_id(0), vec![member(0), first, alias]).err(),
        Some(QuorumTopologyError::DuplicateEndpoint)
    );
}

#[test]
fn legacy_numeric_ipv4_aliases_are_rejected() {
    for alias in [
        "127.000.000.001",
        "127.1",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
    ] {
        assert_eq!(
            ReplicaEndpoint::new(alias, 7443).err(),
            Some(QuorumTopologyError::InvalidField {
                field: ReplicaTopologyField::Endpoint,
                reason: ReplicaTopologyFieldError::Malformed,
            }),
            "legacy numeric IPv4 alias must fail: {alias}"
        );
    }

    let strict = ReplicaEndpoint::new("127.0.0.1", 7443).expect("strict IPv4 literal");
    assert_eq!(strict.host(), "127.0.0.1");
    assert!(ReplicaEndpoint::new("replica-127.test.invalid", 7443).is_ok());

    let maximum_absolute_fqdn = format!(
        "{}.{}.{}.{}.",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let maximum =
        ReplicaEndpoint::new(maximum_absolute_fqdn, 7443).expect("maximum-length absolute FQDN");
    assert_eq!(
        maximum.host().len(),
        ReplicaEndpoint::MAX_CANONICAL_HOST_BYTES
    );
    assert_eq!(
        ReplicaEndpoint::new("a".repeat(254), 7443).err(),
        Some(QuorumTopologyError::InvalidField {
            field: ReplicaTopologyField::Endpoint,
            reason: ReplicaTopologyFieldError::TooLong,
        })
    );
}

#[test]
fn member_order_does_not_change_admission_or_quorum() {
    let mut forward = members(5);
    let mut reverse = members(5);
    reverse.reverse();

    let first = validate_ha(replica_id(2), std::mem::take(&mut forward)).expect("forward");
    let second = validate_ha(replica_id(2), reverse).expect("reverse");
    assert_eq!(first.summary(), second.summary());
}

#[test]
fn lab_singleton_topology_never_advertises_ha() {
    let local = replica_id(0);
    let configured = vec![member(0)];
    let topology = ValidatedQuorumTopology::try_new_consensus_lab_singleton(
        local.clone(),
        configured.clone(),
        consensus_identity(&configured),
    )
    .expect("explicit consensus singleton");
    assert_eq!(topology.summary().mode(), QuorumTopologyMode::LabSingleton);
    assert_eq!(topology.summary().required_quorum(), 1);
    assert_eq!(
        topology.platform_profile(),
        SessionStorePlatformProfile::SingleReplica
    );
    assert_eq!(topology.summary().local_replica_id(), Some(&local));

    let empty = Vec::new();
    assert_eq!(
        ValidatedQuorumTopology::try_new_consensus_lab_singleton(
            replica_id(0),
            empty.clone(),
            consensus_identity(&empty),
        )
        .err(),
        Some(QuorumTopologyError::LabMemberCount { configured: 0 })
    );
    let two = members(2);
    assert_eq!(
        ValidatedQuorumTopology::try_new_consensus_lab_singleton(
            replica_id(0),
            two.clone(),
            consensus_identity(&two),
        )
        .err(),
        Some(QuorumTopologyError::LabMemberCount { configured: 2 })
    );
}

#[test]
fn topology_errors_and_debug_output_redact_declared_values() {
    let endpoint_canary = "secret-peer.internal.example";
    let tls_canary = "spiffe://sensitive/tenant/replica";
    let descriptor = QuorumReplicaDescriptor::new(
        ReplicaId::new("sensitive-replica-id").expect("ID"),
        ReplicaEndpoint::new(endpoint_canary, 7443).expect("endpoint"),
        ReplicaTlsIdentity::new(tls_canary).expect("TLS identity"),
        ReplicaFailureDomain::new("sensitive-rack").expect("failure domain"),
        ReplicaBackingIdentity::new("sensitive-pvc-uid").expect("backing identity"),
    );
    let debug = format!("{descriptor:?}");
    assert!(!debug.contains(endpoint_canary));
    assert!(!debug.contains(tls_canary));
    assert!(!debug.contains("sensitive-pvc-uid"));

    let invalid = ReplicaEndpoint::new(format!(" {endpoint_canary}"), 7443)
        .expect_err("non-canonical endpoint");
    let display = invalid.to_string();
    assert!(!display.contains(endpoint_canary));
}
