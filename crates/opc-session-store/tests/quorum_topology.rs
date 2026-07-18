use std::time::Duration;

use opc_consensus::{
    derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
};
use opc_session_store::{
    ObservedPhysicalNodeIdentity, QuorumReplicaDescriptor, QuorumTopologyAttestor,
    QuorumTopologyConfig, QuorumTopologyError, QuorumTopologyMode, ReplicaBackingIdentity,
    ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, ReplicaTopologyField,
    ReplicaTopologyFieldError, SessionStorePlatformProfile, TopologyAttestationBuildError,
    TopologyAttestationClaims, TopologyAttestationEvidence, TopologyAttestationPolicy,
    TopologyAttestationProvenance, TopologyAttestationResult, TopologyAttestationTime,
    TopologyAttestationVerificationError, TopologyAttestationVerificationInput,
    TopologyCollectorId, ValidatedQuorumTopology, QUORUM_TOPOLOGY_MAX_MEMBERS,
    TOPOLOGY_ATTESTATION_MAX_PROOF_BYTES, TOPOLOGY_ATTESTATION_MAX_TRUSTED_COLLECTORS,
    TOPOLOGY_ATTESTATION_MAX_VALIDITY,
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
    consensus_identity_at_epoch(members, 1)
}

fn consensus_identity_at_epoch(
    members: &[QuorumReplicaDescriptor],
    epoch: u64,
) -> ConsensusIdentity {
    let cluster_id = ConsensusClusterId::new("session-store-topology-tests").expect("cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(epoch).expect("configuration epoch");
    let fingerprints = members
        .iter()
        .map(QuorumReplicaDescriptor::configuration_fingerprint)
        .collect::<Vec<_>>();
    let configuration_id = derive_configuration_id(cluster_id, epoch, &fingerprints);
    ConsensusIdentity::new(cluster_id, configuration_id, epoch)
}

#[derive(Debug)]
struct DeterministicDigestAttestor;

impl QuorumTopologyAttestor for DeterministicDigestAttestor {
    fn verify(
        &self,
        input: TopologyAttestationVerificationInput<'_>,
    ) -> Result<(), TopologyAttestationVerificationError> {
        (input.proof() == input.canonical_digest())
            .then_some(())
            .ok_or(TopologyAttestationVerificationError::InvalidProof)
    }
}

#[derive(Debug)]
struct RedactionCanaryAttestor {
    canaries: Vec<&'static str>,
}

impl QuorumTopologyAttestor for RedactionCanaryAttestor {
    fn verify(
        &self,
        input: TopologyAttestationVerificationInput<'_>,
    ) -> Result<(), TopologyAttestationVerificationError> {
        let debug = format!("{input:?}");
        for canary in &self.canaries {
            assert!(!debug.contains(canary));
        }
        (input.proof() == input.canonical_digest())
            .then_some(())
            .ok_or(TopologyAttestationVerificationError::InvalidProof)
    }
}

#[allow(clippy::too_many_arguments)]
fn evidence_for(
    descriptor: &QuorumReplicaDescriptor,
    identity: ConsensusIdentity,
    collector_id: TopologyCollectorId,
    provenance: TopologyAttestationProvenance,
    physical_node_index: usize,
    failure_domain: ReplicaFailureDomain,
    backing_identity: ReplicaBackingIdentity,
    observed_at: TopologyAttestationTime,
    expires_at: TopologyAttestationTime,
) -> TopologyAttestationEvidence {
    let claims = TopologyAttestationClaims::new(
        descriptor.replica_id().clone(),
        descriptor.tls_identity().clone(),
        ObservedPhysicalNodeIdentity::new(format!("physical-node-{physical_node_index}"))
            .expect("physical node identity"),
        failure_domain,
        backing_identity,
        descriptor.configuration_fingerprint(),
        identity,
        collector_id,
        provenance,
        observed_at,
        expires_at,
    );
    let proof = claims.canonical_digest().to_vec();
    TopologyAttestationEvidence::try_new(claims, proof).expect("bounded evidence")
}

fn conforming_evidence(
    configured: &[QuorumReplicaDescriptor],
    identity: ConsensusIdentity,
    collector_id: &TopologyCollectorId,
    provenance: TopologyAttestationProvenance,
    observed_at: TopologyAttestationTime,
    expires_at: TopologyAttestationTime,
) -> Vec<TopologyAttestationEvidence> {
    configured
        .iter()
        .enumerate()
        .map(|(index, descriptor)| {
            evidence_for(
                descriptor,
                identity,
                collector_id.clone(),
                provenance,
                index,
                descriptor.failure_domain().clone(),
                descriptor.backing_identity().clone(),
                observed_at,
                expires_at,
            )
        })
        .collect()
}

fn attest(
    configured: Vec<QuorumReplicaDescriptor>,
    identity: ConsensusIdentity,
    evidence: Vec<TopologyAttestationEvidence>,
    collector_id: TopologyCollectorId,
    provenance: TopologyAttestationProvenance,
    now: TopologyAttestationTime,
) -> Result<ValidatedQuorumTopology, QuorumTopologyError> {
    let policy = TopologyAttestationPolicy::try_new(
        provenance,
        vec![collector_id],
        Duration::from_secs(120),
    )
    .expect("attestation policy");
    ValidatedQuorumTopology::try_from_attested(
        QuorumTopologyConfig::new_consensus(replica_id(0), configured, identity),
        evidence,
        &policy,
        &DeterministicDigestAttestor,
        now,
    )
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
fn descriptor_only_three_node_topology_is_explicitly_lab_labelled() {
    let descriptors = test_descriptors();
    let local = descriptors[0].replica_id().clone();
    let identity = consensus_identity(&descriptors);

    let topology =
        validate_ha(local, descriptors.clone()).expect("descriptor-only lab topology admission");

    assert_eq!(topology.members(), descriptors.as_slice());
    assert_eq!(topology.summary().configured_members(), 3);
    assert_eq!(
        topology.platform_profile(),
        SessionStorePlatformProfile::Unknown
    );
    assert_eq!(topology.summary().mode().as_str(), "descriptor-only-lab-ha");
    let summary = topology
        .summary()
        .attestation_at(TopologyAttestationTime::from_unix_seconds(1_000));
    assert_eq!(
        summary.provenance(),
        TopologyAttestationProvenance::UnverifiedConfiguration
    );
    assert_eq!(
        summary.result(),
        TopologyAttestationResult::DescriptorOnlyLab
    );

    let collector = TopologyCollectorId::new("platform-attestor-a").expect("collector");
    let policy = TopologyAttestationPolicy::try_new(
        TopologyAttestationProvenance::AuthenticatedPlatform,
        vec![collector.clone()],
        Duration::from_secs(120),
    )
    .expect("attestation policy");
    let evidence = conforming_evidence(
        &descriptors,
        identity,
        &collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(1_000),
        TopologyAttestationTime::from_unix_seconds(1_100),
    );
    assert_eq!(
        topology
            .verify_attestation_evidence(
                evidence,
                &policy,
                &DeterministicDigestAttestor,
                TopologyAttestationTime::from_unix_seconds(1_001),
            )
            .err(),
        Some(QuorumTopologyError::TopologyEvidenceRequiresAttestedHa),
        "authenticated evidence must not upgrade a descriptor-only topology"
    );
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
            SessionStorePlatformProfile::Unknown
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

#[test]
fn attested_three_and_five_member_topologies_admit_with_fresh_exact_evidence() {
    for count in [3, 5] {
        let configured = members(count);
        let identity = consensus_identity(&configured);
        let collector = TopologyCollectorId::new("deterministic-conformance-collector")
            .expect("collector identity");
        let observed_at = TopologyAttestationTime::from_unix_seconds(1_000);
        let expires_at = TopologyAttestationTime::from_unix_seconds(1_300);
        let evidence = conforming_evidence(
            &configured,
            identity,
            &collector,
            TopologyAttestationProvenance::DeterministicConformance,
            observed_at,
            expires_at,
        );

        let topology = attest(
            configured,
            identity,
            evidence,
            collector,
            TopologyAttestationProvenance::DeterministicConformance,
            TopologyAttestationTime::from_unix_seconds(1_030),
        )
        .expect("fresh exact evidence must admit");

        assert_eq!(topology.summary().mode(), QuorumTopologyMode::AttestedHa);
        assert_eq!(topology.summary().configured_members(), count);
        assert_eq!(
            topology.platform_profile(),
            SessionStorePlatformProfile::Unknown
        );
        let summary = topology
            .summary()
            .attestation_at(TopologyAttestationTime::from_unix_seconds(1_030));
        assert_eq!(summary.configuration_epoch(), 1);
        assert_eq!(
            summary.provenance(),
            TopologyAttestationProvenance::DeterministicConformance
        );
        assert_eq!(summary.result(), TopologyAttestationResult::Verified);
        let freshness = summary.freshness().expect("verified freshness");
        assert_eq!(freshness.oldest_observation_age(), Duration::from_secs(30));
        assert_eq!(freshness.valid_for(), Duration::from_secs(90));
        assert!(!summary.is_production_verified());
    }
}

#[test]
fn authenticated_platform_evidence_is_production_eligible_until_freshness_expires() {
    let configured = members(3);
    let identity = consensus_identity(&configured);
    let collector = TopologyCollectorId::new("platform-attestor-a").expect("collector identity");
    let evidence = conforming_evidence(
        &configured,
        identity,
        &collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(2_000),
        TopologyAttestationTime::from_unix_seconds(2_600),
    );
    let topology = attest(
        configured,
        identity,
        evidence,
        collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(2_010),
    )
    .expect("authenticated evidence");

    assert!(topology
        .summary()
        .attestation_at(TopologyAttestationTime::from_unix_seconds(2_119))
        .is_production_verified());
    assert_eq!(
        topology
            .summary()
            .attestation_at(TopologyAttestationTime::from_unix_seconds(2_120))
            .result(),
        TopologyAttestationResult::Expired
    );
}

#[test]
fn exact_topology_can_refresh_expiring_evidence_without_membership_change() {
    let configured = members(3);
    let identity = consensus_identity(&configured);
    let collector = TopologyCollectorId::new("platform-attestor-a").expect("collector identity");
    let initial_evidence = conforming_evidence(
        &configured,
        identity,
        &collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(2_000),
        TopologyAttestationTime::from_unix_seconds(2_600),
    );
    let topology = attest(
        configured.clone(),
        identity,
        initial_evidence,
        collector.clone(),
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(2_010),
    )
    .expect("initial authenticated evidence");
    assert_eq!(
        topology
            .summary()
            .attestation_at(TopologyAttestationTime::from_unix_seconds(2_200))
            .result(),
        TopologyAttestationResult::Expired
    );

    let refreshed_evidence = conforming_evidence(
        &configured,
        identity,
        &collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(2_190),
        TopologyAttestationTime::from_unix_seconds(2_600),
    );
    let policy = TopologyAttestationPolicy::try_new(
        TopologyAttestationProvenance::AuthenticatedPlatform,
        vec![collector],
        Duration::from_secs(120),
    )
    .expect("refresh policy");
    let refreshed = topology
        .verify_attestation_evidence(
            refreshed_evidence,
            &policy,
            &DeterministicDigestAttestor,
            TopologyAttestationTime::from_unix_seconds(2_200),
        )
        .expect("refresh exact immutable topology evidence");
    assert!(refreshed
        .summary_at(TopologyAttestationTime::from_unix_seconds(2_250))
        .is_production_verified());
}

#[test]
fn duplicate_observed_node_failure_domain_and_backing_each_fail_closed() {
    let cases = [
        QuorumTopologyError::DuplicateObservedPhysicalNode,
        QuorumTopologyError::DuplicateObservedFailureDomain,
        QuorumTopologyError::DuplicateObservedBackingIdentity,
    ];
    for expected in cases {
        let configured = members(3);
        let identity = consensus_identity(&configured);
        let collector = TopologyCollectorId::new("platform-attestor-a").expect("collector");
        let mut evidence = conforming_evidence(
            &configured,
            identity,
            &collector,
            TopologyAttestationProvenance::AuthenticatedPlatform,
            TopologyAttestationTime::from_unix_seconds(3_000),
            TopologyAttestationTime::from_unix_seconds(3_100),
        );
        let physical_node = if expected == QuorumTopologyError::DuplicateObservedPhysicalNode {
            0
        } else {
            1
        };
        let failure_domain = if expected == QuorumTopologyError::DuplicateObservedFailureDomain {
            configured[0].failure_domain().clone()
        } else {
            configured[1].failure_domain().clone()
        };
        let backing = if expected == QuorumTopologyError::DuplicateObservedBackingIdentity {
            configured[0].backing_identity().clone()
        } else {
            configured[1].backing_identity().clone()
        };
        evidence[1] = evidence_for(
            &configured[1],
            identity,
            collector.clone(),
            TopologyAttestationProvenance::AuthenticatedPlatform,
            physical_node,
            failure_domain,
            backing,
            TopologyAttestationTime::from_unix_seconds(3_000),
            TopologyAttestationTime::from_unix_seconds(3_100),
        );

        assert_eq!(
            attest(
                configured,
                identity,
                evidence,
                collector,
                TopologyAttestationProvenance::AuthenticatedPlatform,
                TopologyAttestationTime::from_unix_seconds(3_010),
            )
            .err(),
            Some(expected)
        );
    }
}

#[test]
fn wrong_member_tls_backing_and_descriptor_bindings_fail_closed() {
    let expected_errors = [
        QuorumTopologyError::UnexpectedTopologyEvidenceMember,
        QuorumTopologyError::TopologyEvidenceTlsIdentityMismatch,
        QuorumTopologyError::TopologyEvidenceFailureDomainMismatch,
        QuorumTopologyError::TopologyEvidenceBackingIdentityMismatch,
        QuorumTopologyError::TopologyEvidenceDescriptorMismatch,
    ];
    for expected in expected_errors {
        let configured = members(3);
        let identity = consensus_identity(&configured);
        let collector = TopologyCollectorId::new("platform-attestor-a").expect("collector");
        let mut evidence = conforming_evidence(
            &configured,
            identity,
            &collector,
            TopologyAttestationProvenance::AuthenticatedPlatform,
            TopologyAttestationTime::from_unix_seconds(4_000),
            TopologyAttestationTime::from_unix_seconds(4_100),
        );
        let source = if expected == QuorumTopologyError::UnexpectedTopologyEvidenceMember {
            member(99)
        } else {
            configured[1].clone()
        };
        let claims = TopologyAttestationClaims::new(
            source.replica_id().clone(),
            if expected == QuorumTopologyError::TopologyEvidenceTlsIdentityMismatch {
                configured[0].tls_identity().clone()
            } else {
                source.tls_identity().clone()
            },
            ObservedPhysicalNodeIdentity::new("replacement-physical-node").expect("physical node"),
            if expected == QuorumTopologyError::TopologyEvidenceFailureDomainMismatch {
                ReplicaFailureDomain::new("unexpected-but-distinct-failure-domain")
                    .expect("unexpected failure domain")
            } else {
                source.failure_domain().clone()
            },
            if expected == QuorumTopologyError::TopologyEvidenceBackingIdentityMismatch {
                ReplicaBackingIdentity::new("unexpected-but-distinct-backing")
                    .expect("unexpected backing")
            } else {
                source.backing_identity().clone()
            },
            if expected == QuorumTopologyError::TopologyEvidenceDescriptorMismatch {
                configured[0].configuration_fingerprint()
            } else {
                source.configuration_fingerprint()
            },
            identity,
            collector.clone(),
            TopologyAttestationProvenance::AuthenticatedPlatform,
            TopologyAttestationTime::from_unix_seconds(4_000),
            TopologyAttestationTime::from_unix_seconds(4_100),
        );
        let proof = claims.canonical_digest().to_vec();
        evidence[1] =
            TopologyAttestationEvidence::try_new(claims, proof).expect("replacement evidence");

        assert_eq!(
            attest(
                configured,
                identity,
                evidence,
                collector,
                TopologyAttestationProvenance::AuthenticatedPlatform,
                TopologyAttestationTime::from_unix_seconds(4_010),
            )
            .err(),
            Some(expected)
        );
    }
}

#[test]
fn stale_epoch_expiry_untrusted_collector_and_invalid_proof_fail_closed() {
    let expected_errors = [
        QuorumTopologyError::TopologyEvidenceEpochMismatch,
        QuorumTopologyError::TopologyEvidenceExpired,
        QuorumTopologyError::UntrustedTopologyEvidenceCollector,
        QuorumTopologyError::TopologyEvidenceVerificationFailed,
    ];
    for expected in expected_errors {
        let configured = members(3);
        let admitted_identity = consensus_identity_at_epoch(&configured, 2);
        let evidence_identity = if expected == QuorumTopologyError::TopologyEvidenceEpochMismatch {
            consensus_identity_at_epoch(&configured, 1)
        } else {
            admitted_identity
        };
        let trusted = TopologyCollectorId::new("trusted-platform-attestor").expect("collector");
        let token_collector = if expected == QuorumTopologyError::UntrustedTopologyEvidenceCollector
        {
            TopologyCollectorId::new("untrusted-platform-attestor").expect("collector")
        } else {
            trusted.clone()
        };
        let expires_at = if expected == QuorumTopologyError::TopologyEvidenceExpired {
            TopologyAttestationTime::from_unix_seconds(5_005)
        } else {
            TopologyAttestationTime::from_unix_seconds(5_100)
        };
        let mut evidence = conforming_evidence(
            &configured,
            evidence_identity,
            &token_collector,
            TopologyAttestationProvenance::AuthenticatedPlatform,
            TopologyAttestationTime::from_unix_seconds(5_000),
            expires_at,
        );
        if expected == QuorumTopologyError::TopologyEvidenceVerificationFailed {
            let claims = TopologyAttestationClaims::new(
                configured[0].replica_id().clone(),
                configured[0].tls_identity().clone(),
                ObservedPhysicalNodeIdentity::new("physical-node-0").expect("physical node"),
                configured[0].failure_domain().clone(),
                configured[0].backing_identity().clone(),
                configured[0].configuration_fingerprint(),
                admitted_identity,
                trusted.clone(),
                TopologyAttestationProvenance::AuthenticatedPlatform,
                TopologyAttestationTime::from_unix_seconds(5_000),
                TopologyAttestationTime::from_unix_seconds(5_100),
            );
            evidence[0] = TopologyAttestationEvidence::try_new(claims, vec![0x55])
                .expect("malformed authenticated proof");
        }

        assert_eq!(
            attest(
                configured,
                admitted_identity,
                evidence,
                trusted,
                TopologyAttestationProvenance::AuthenticatedPlatform,
                TopologyAttestationTime::from_unix_seconds(5_010),
            )
            .err(),
            Some(expected)
        );
    }
}

#[test]
fn unexpired_old_epoch_evidence_cannot_admit_new_configuration_epoch() {
    let old_members = members(3);
    let old_identity = consensus_identity_at_epoch(&old_members, 1);
    let collector = TopologyCollectorId::new("platform-attestor-a").expect("collector");
    let old_evidence = conforming_evidence(
        &old_members,
        old_identity,
        &collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(6_000),
        TopologyAttestationTime::from_unix_seconds(6_100),
    );
    let epoch_two_identity = consensus_identity_at_epoch(&old_members, 2);
    assert_eq!(
        attest(
            old_members.clone(),
            epoch_two_identity,
            old_evidence,
            collector.clone(),
            TopologyAttestationProvenance::AuthenticatedPlatform,
            TopologyAttestationTime::from_unix_seconds(6_010),
        )
        .err(),
        Some(QuorumTopologyError::TopologyEvidenceEpochMismatch)
    );
}

#[test]
fn unexpired_old_backing_claim_cannot_admit_replacement() {
    let old_members = members(3);
    let collector = TopologyCollectorId::new("platform-attestor-a").expect("collector");
    let mut replacement_members = old_members;
    replacement_members[1] = descriptor(replica_id(1), 1, 1, 1, 99);
    let replacement_identity = consensus_identity_at_epoch(&replacement_members, 2);
    let mut replacement_evidence = conforming_evidence(
        &replacement_members,
        replacement_identity,
        &collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(6_000),
        TopologyAttestationTime::from_unix_seconds(6_100),
    );
    replacement_evidence[1] = evidence_for(
        &replacement_members[1],
        replacement_identity,
        collector.clone(),
        TopologyAttestationProvenance::AuthenticatedPlatform,
        1,
        replacement_members[1].failure_domain().clone(),
        ReplicaBackingIdentity::new("test-backing-1").expect("old backing"),
        TopologyAttestationTime::from_unix_seconds(6_000),
        TopologyAttestationTime::from_unix_seconds(6_100),
    );
    assert_eq!(
        attest(
            replacement_members,
            replacement_identity,
            replacement_evidence,
            collector,
            TopologyAttestationProvenance::AuthenticatedPlatform,
            TopologyAttestationTime::from_unix_seconds(6_010),
        )
        .err(),
        Some(QuorumTopologyError::TopologyEvidenceBackingIdentityMismatch)
    );
}

#[test]
fn expired_evidence_cannot_be_readmitted_and_replacement_evidence_can() {
    let configured = members(3);
    let identity = consensus_identity(&configured);
    let collector = TopologyCollectorId::new("platform-attestor-a").expect("collector");
    let old_evidence = conforming_evidence(
        &configured,
        identity,
        &collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(6_500),
        TopologyAttestationTime::from_unix_seconds(6_510),
    );
    let old_topology = attest(
        configured.clone(),
        identity,
        old_evidence.clone(),
        collector.clone(),
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(6_500),
    )
    .expect("initial topology admission");
    assert_eq!(
        old_topology
            .summary()
            .attestation_at(TopologyAttestationTime::from_unix_seconds(6_510))
            .result(),
        TopologyAttestationResult::Expired
    );
    assert_eq!(
        attest(
            configured.clone(),
            identity,
            old_evidence,
            collector.clone(),
            TopologyAttestationProvenance::AuthenticatedPlatform,
            TopologyAttestationTime::from_unix_seconds(6_510),
        )
        .err(),
        Some(QuorumTopologyError::TopologyEvidenceExpired),
        "a later admission must not revive expired evidence"
    );

    let fresh_evidence = conforming_evidence(
        &configured,
        identity,
        &collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(6_510),
        TopologyAttestationTime::from_unix_seconds(6_520),
    );
    let readmitted = attest(
        configured,
        identity,
        fresh_evidence,
        collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(6_510),
    )
    .expect("replacement topology evidence admission");
    assert!(readmitted
        .summary()
        .attestation_at(TopologyAttestationTime::from_unix_seconds(6_511))
        .is_production_verified());
}

#[test]
fn evidence_debug_and_errors_do_not_expose_platform_fact_canaries() {
    let configured = members(3);
    let identity = consensus_identity(&configured);
    let collector_canary = "collector-secret-canary";
    let physical_canary = "physical-node-secret-canary";
    let backing_canary = "backing-secret-canary";
    let failure_domain_canary = "failure-domain-secret-canary";
    let collector = TopologyCollectorId::new(collector_canary).expect("collector");
    let claims = TopologyAttestationClaims::new(
        configured[0].replica_id().clone(),
        configured[0].tls_identity().clone(),
        ObservedPhysicalNodeIdentity::new(physical_canary).expect("physical node"),
        ReplicaFailureDomain::new(failure_domain_canary).expect("failure domain"),
        ReplicaBackingIdentity::new(backing_canary).expect("backing"),
        configured[0].configuration_fingerprint(),
        identity,
        collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(7_000),
        TopologyAttestationTime::from_unix_seconds(7_100),
    );
    let evidence =
        TopologyAttestationEvidence::try_new(claims, vec![0xaa]).expect("bounded evidence");
    let debug = format!("{evidence:?}");
    assert!(!debug.contains(collector_canary));
    assert!(!debug.contains(physical_canary));
    assert!(!debug.contains(backing_canary));
    assert!(!debug.contains(failure_domain_canary));
    assert!(!debug.contains(configured[0].replica_id().as_str()));
    assert!(!debug.contains(configured[0].tls_identity().as_str()));

    let error = QuorumTopologyError::TopologyEvidenceVerificationFailed.to_string();
    assert!(!error.contains(collector_canary));
    assert!(!error.contains(physical_canary));
    assert!(!error.contains(backing_canary));
    assert!(!error.contains(failure_domain_canary));
}

#[test]
fn every_attestation_debug_and_summary_surface_redacts_identity_canaries() {
    const MEMBER: &str = "member-secret-canary";
    const TLS: &str = "spiffe://test/session/tls-secret-canary";
    const PHYSICAL: &str = "physical-secret-canary";
    const FAILURE_DOMAIN: &str = "failure-domain-secret-canary";
    const BACKING: &str = "backing-secret-canary";
    const COLLECTOR: &str = "collector-secret-canary";
    let canaries = vec![MEMBER, TLS, PHYSICAL, FAILURE_DOMAIN, BACKING, COLLECTOR];
    let mut configured = members(3);
    configured[0] = QuorumReplicaDescriptor::new(
        ReplicaId::new(MEMBER).expect("member"),
        ReplicaEndpoint::new("redaction.test.invalid", 7443).expect("endpoint"),
        ReplicaTlsIdentity::new(TLS).expect("TLS identity"),
        ReplicaFailureDomain::new(FAILURE_DOMAIN).expect("failure domain"),
        ReplicaBackingIdentity::new(BACKING).expect("backing identity"),
    );
    let identity = consensus_identity(&configured);
    let collector = TopologyCollectorId::new(COLLECTOR).expect("collector");
    let physical = ObservedPhysicalNodeIdentity::new(PHYSICAL).expect("physical node");
    let claims = TopologyAttestationClaims::new(
        configured[0].replica_id().clone(),
        configured[0].tls_identity().clone(),
        physical.clone(),
        configured[0].failure_domain().clone(),
        configured[0].backing_identity().clone(),
        configured[0].configuration_fingerprint(),
        identity,
        collector.clone(),
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(7_000),
        TopologyAttestationTime::from_unix_seconds(7_100),
    );
    let proof = claims.canonical_digest().to_vec();
    let first_evidence =
        TopologyAttestationEvidence::try_new(claims.clone(), proof).expect("evidence");
    let mut evidence = conforming_evidence(
        &configured,
        identity,
        &collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(7_000),
        TopologyAttestationTime::from_unix_seconds(7_100),
    );
    evidence[0] = first_evidence.clone();
    let policy = TopologyAttestationPolicy::try_new(
        TopologyAttestationProvenance::AuthenticatedPlatform,
        vec![collector.clone()],
        Duration::from_secs(60),
    )
    .expect("policy");
    let attestor = RedactionCanaryAttestor {
        canaries: canaries.clone(),
    };
    let topology = ValidatedQuorumTopology::try_from_attested(
        QuorumTopologyConfig::new_consensus(
            configured[0].replica_id().clone(),
            configured.clone(),
            identity,
        ),
        evidence.clone(),
        &policy,
        &attestor,
        TopologyAttestationTime::from_unix_seconds(7_010),
    )
    .expect("attested topology");
    let refreshed = topology
        .verify_attestation_evidence(
            evidence,
            &policy,
            &attestor,
            TopologyAttestationTime::from_unix_seconds(7_010),
        )
        .expect("verified attestation");
    let summary = topology
        .summary()
        .attestation_at(TopologyAttestationTime::from_unix_seconds(7_011));
    let debug_surfaces = [
        format!("{collector:?}"),
        format!("{physical:?}"),
        format!("{claims:?}"),
        format!("{first_evidence:?}"),
        format!("{policy:?}"),
        format!("{summary:?}"),
        format!("{refreshed:?}"),
    ];
    for debug in debug_surfaces {
        for canary in &canaries {
            assert!(!debug.contains(canary));
        }
    }
}

#[test]
fn evidence_set_cardinality_provenance_and_time_bounds_fail_closed() {
    let expected_errors = [
        QuorumTopologyError::TopologyEvidenceCountMismatch,
        QuorumTopologyError::DuplicateTopologyEvidenceMember,
        QuorumTopologyError::TopologyEvidenceProvenanceMismatch,
        QuorumTopologyError::TopologyEvidenceNotYetValid,
        QuorumTopologyError::TopologyEvidenceValidityInvalid,
    ];
    for expected in expected_errors {
        let configured = members(3);
        let identity = consensus_identity(&configured);
        let collector = TopologyCollectorId::new("platform-attestor-a").expect("collector");
        let observed_at = if expected == QuorumTopologyError::TopologyEvidenceNotYetValid {
            TopologyAttestationTime::from_unix_seconds(8_020)
        } else {
            TopologyAttestationTime::from_unix_seconds(8_000)
        };
        let expires_at = if expected == QuorumTopologyError::TopologyEvidenceValidityInvalid {
            TopologyAttestationTime::from_unix_seconds(
                8_000 + TOPOLOGY_ATTESTATION_MAX_VALIDITY.as_secs() + 1,
            )
        } else {
            TopologyAttestationTime::from_unix_seconds(8_100)
        };
        let token_provenance =
            if expected == QuorumTopologyError::TopologyEvidenceProvenanceMismatch {
                TopologyAttestationProvenance::DeterministicConformance
            } else {
                TopologyAttestationProvenance::AuthenticatedPlatform
            };
        let mut evidence = conforming_evidence(
            &configured,
            identity,
            &collector,
            token_provenance,
            observed_at,
            expires_at,
        );
        if expected == QuorumTopologyError::TopologyEvidenceCountMismatch {
            evidence.pop();
        } else if expected == QuorumTopologyError::DuplicateTopologyEvidenceMember {
            evidence[1] = evidence[0].clone();
        }

        assert_eq!(
            attest(
                configured,
                identity,
                evidence,
                collector,
                TopologyAttestationProvenance::AuthenticatedPlatform,
                TopologyAttestationTime::from_unix_seconds(8_010),
            )
            .err(),
            Some(expected)
        );
    }
}

#[test]
fn proof_and_policy_allocations_are_bounded_at_construction() {
    let configured = members(3);
    let descriptor = &configured[0];
    let identity = consensus_identity(&configured);
    let collector = TopologyCollectorId::new("platform-attestor-a").expect("collector");
    let claims = TopologyAttestationClaims::new(
        descriptor.replica_id().clone(),
        descriptor.tls_identity().clone(),
        ObservedPhysicalNodeIdentity::new("physical-node-0").expect("node"),
        descriptor.failure_domain().clone(),
        descriptor.backing_identity().clone(),
        descriptor.configuration_fingerprint(),
        identity,
        collector.clone(),
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(9_000),
        TopologyAttestationTime::from_unix_seconds(9_100),
    );
    assert_eq!(
        TopologyAttestationEvidence::try_new(claims.clone(), Vec::new()).err(),
        Some(TopologyAttestationBuildError::InvalidProofLength)
    );
    assert_eq!(
        TopologyAttestationEvidence::try_new(
            claims,
            vec![0; TOPOLOGY_ATTESTATION_MAX_PROOF_BYTES + 1],
        )
        .err(),
        Some(TopologyAttestationBuildError::InvalidProofLength)
    );
    assert_eq!(
        TopologyAttestationPolicy::try_new(
            TopologyAttestationProvenance::UnverifiedConfiguration,
            vec![collector.clone()],
            Duration::from_secs(1),
        )
        .err(),
        Some(TopologyAttestationBuildError::InvalidPolicy)
    );
    assert_eq!(
        TopologyAttestationPolicy::try_new(
            TopologyAttestationProvenance::AuthenticatedPlatform,
            vec![collector.clone(), collector.clone()],
            Duration::from_secs(1),
        )
        .err(),
        Some(TopologyAttestationBuildError::InvalidPolicy)
    );
    let too_many_collectors = (0..=TOPOLOGY_ATTESTATION_MAX_TRUSTED_COLLECTORS)
        .map(|index| {
            TopologyCollectorId::new(format!("platform-attestor-{index}"))
                .expect("bounded collector identity")
        })
        .collect();
    assert_eq!(
        TopologyAttestationPolicy::try_new(
            TopologyAttestationProvenance::AuthenticatedPlatform,
            too_many_collectors,
            Duration::from_secs(1),
        )
        .err(),
        Some(TopologyAttestationBuildError::InvalidPolicy)
    );
    assert_eq!(
        TopologyAttestationPolicy::try_new(
            TopologyAttestationProvenance::AuthenticatedPlatform,
            vec![collector.clone()],
            Duration::new(1, 1),
        )
        .err(),
        Some(TopologyAttestationBuildError::InvalidPolicy)
    );
    assert_eq!(
        TopologyAttestationPolicy::try_new(
            TopologyAttestationProvenance::AuthenticatedPlatform,
            vec![collector],
            Duration::from_secs(u64::MAX),
        )
        .err(),
        Some(TopologyAttestationBuildError::InvalidPolicy)
    );
}

#[test]
fn canonical_attestation_digest_is_stable_and_time_bound() {
    let configured = members(3);
    let descriptor = &configured[0];
    let identity = consensus_identity(&configured);
    let collector = TopologyCollectorId::new("canonical-vector-collector").expect("collector");
    let claims = TopologyAttestationClaims::new(
        descriptor.replica_id().clone(),
        descriptor.tls_identity().clone(),
        ObservedPhysicalNodeIdentity::new("canonical-vector-node").expect("node"),
        descriptor.failure_domain().clone(),
        descriptor.backing_identity().clone(),
        descriptor.configuration_fingerprint(),
        identity,
        collector.clone(),
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(10_000),
        TopologyAttestationTime::from_unix_seconds(10_100),
    );
    assert_eq!(
        claims.canonical_digest(),
        [
            209, 243, 251, 122, 146, 83, 233, 57, 173, 170, 40, 50, 245, 195, 24, 3, 6, 214, 132,
            199, 239, 83, 216, 244, 3, 173, 93, 93, 135, 115, 97, 145,
        ]
    );

    let later = TopologyAttestationClaims::new(
        descriptor.replica_id().clone(),
        descriptor.tls_identity().clone(),
        ObservedPhysicalNodeIdentity::new("canonical-vector-node").expect("node"),
        descriptor.failure_domain().clone(),
        descriptor.backing_identity().clone(),
        descriptor.configuration_fingerprint(),
        identity,
        collector,
        TopologyAttestationProvenance::AuthenticatedPlatform,
        TopologyAttestationTime::from_unix_seconds(10_001),
        TopologyAttestationTime::from_unix_seconds(10_100),
    );
    assert_ne!(claims.canonical_digest(), later.canonical_digest());
}
