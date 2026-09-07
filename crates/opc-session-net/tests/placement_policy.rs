use opc_session_net::{
    SessionClusterId, SessionConfigurationEpoch, SessionConfigurationGeneration,
    SessionManifestError, SessionPlacementDisposition, SessionPlacementPolicy,
    SessionReplicationManifest,
};
use opc_session_store::{
    QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaTlsIdentity,
};

fn descriptor(index: u16, failure_domain: &str) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        ReplicaId::new(format!("replica-{index}")).expect("test replica ID"),
        ReplicaEndpoint::new(format!("replica-{index}.session.invalid"), 7443)
            .expect("test endpoint"),
        ReplicaTlsIdentity::new(format!(
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/smf/instance/{index}"
        ))
        .expect("test TLS identity"),
        ReplicaFailureDomain::new(failure_domain).expect("test failure domain"),
        ReplicaBackingIdentity::new(format!("backing-{index}")).expect("test backing identity"),
    )
}

fn manifest(
    descriptors: Vec<QuorumReplicaDescriptor>,
) -> Result<SessionReplicationManifest, SessionManifestError> {
    SessionReplicationManifest::try_new_with_epoch(
        SessionClusterId::new("placement-policy-cluster").expect("test cluster ID"),
        SessionConfigurationGeneration::new("placement-policy-generation")
            .expect("test generation"),
        SessionConfigurationEpoch::new(7).expect("test epoch"),
        descriptors,
    )
}

fn explicitly_correlated_manifest(
    descriptors: Vec<QuorumReplicaDescriptor>,
) -> Result<SessionReplicationManifest, SessionManifestError> {
    SessionReplicationManifest::try_new_with_epoch_and_placement_policy(
        SessionClusterId::new("placement-policy-cluster").expect("test cluster ID"),
        SessionConfigurationGeneration::new("placement-policy-generation")
            .expect("test generation"),
        SessionConfigurationEpoch::new(7).expect("test epoch"),
        descriptors,
        SessionPlacementPolicy::AllowReducedResilience,
    )
}

#[test]
fn strict_default_rejects_correlated_failure_domains() {
    assert!(matches!(
        manifest(vec![
            descriptor(1, "shared-domain"),
            descriptor(2, "shared-domain"),
            descriptor(3, "independent-domain"),
        ]),
        Err(SessionManifestError::DuplicateFailureDomain)
    ));

    let independent = manifest(vec![
        descriptor(1, "domain-1"),
        descriptor(2, "domain-2"),
        descriptor(3, "domain-3"),
    ])
    .expect("strict default admits independent placement");
    assert_eq!(
        independent.placement_policy(),
        SessionPlacementPolicy::RequireIndependentFailureDomains
    );
    assert_eq!(
        independent.placement_disposition(),
        SessionPlacementDisposition::DistinctDeclaredFailureDomains
    );
}

#[test]
fn explicit_correlated_policy_admits_three_and_five_voter_manifests() {
    for voters in [3, 5] {
        let descriptors = (1..=voters)
            .map(|index| descriptor(index, "shared-domain"))
            .collect();
        let manifest = explicitly_correlated_manifest(descriptors)
            .expect("explicit correlated placement is admitted");

        assert_eq!(manifest.configured_members(), usize::from(voters));
        assert_eq!(
            manifest.placement_policy(),
            SessionPlacementPolicy::AllowReducedResilience
        );
        assert_eq!(
            manifest.placement_disposition(),
            SessionPlacementDisposition::ExplicitlyAllowedCorrelatedFailureDomains
        );
    }
}

#[test]
fn explicit_correlated_policy_retains_all_other_unique_identity_checks() {
    let first = descriptor(1, "shared-domain");

    let duplicate_replica_id = QuorumReplicaDescriptor::new(
        first.replica_id().clone(),
        ReplicaEndpoint::new("replica-2.session.invalid", 7443).expect("test endpoint"),
        descriptor(2, "shared-domain").tls_identity().clone(),
        ReplicaFailureDomain::new("shared-domain").expect("test failure domain"),
        ReplicaBackingIdentity::new("backing-2").expect("test backing identity"),
    );
    assert!(matches!(
        explicitly_correlated_manifest(vec![first.clone(), duplicate_replica_id]),
        Err(SessionManifestError::DuplicateReplicaId)
    ));

    let duplicate_endpoint = QuorumReplicaDescriptor::new(
        ReplicaId::new("replica-2").expect("test replica ID"),
        first.endpoint().clone(),
        descriptor(2, "shared-domain").tls_identity().clone(),
        ReplicaFailureDomain::new("shared-domain").expect("test failure domain"),
        ReplicaBackingIdentity::new("backing-2").expect("test backing identity"),
    );
    assert!(matches!(
        explicitly_correlated_manifest(vec![first.clone(), duplicate_endpoint]),
        Err(SessionManifestError::DuplicateEndpoint)
    ));

    let duplicate_tls_identity = QuorumReplicaDescriptor::new(
        ReplicaId::new("replica-2").expect("test replica ID"),
        ReplicaEndpoint::new("replica-2.session.invalid", 7443).expect("test endpoint"),
        first.tls_identity().clone(),
        ReplicaFailureDomain::new("shared-domain").expect("test failure domain"),
        ReplicaBackingIdentity::new("backing-2").expect("test backing identity"),
    );
    assert!(matches!(
        explicitly_correlated_manifest(vec![first.clone(), duplicate_tls_identity]),
        Err(SessionManifestError::DuplicateTlsIdentity)
    ));

    let duplicate_backing_identity = QuorumReplicaDescriptor::new(
        ReplicaId::new("replica-2").expect("test replica ID"),
        ReplicaEndpoint::new("replica-2.session.invalid", 7443).expect("test endpoint"),
        descriptor(2, "shared-domain").tls_identity().clone(),
        ReplicaFailureDomain::new("shared-domain").expect("test failure domain"),
        first.backing_identity().clone(),
    );
    assert!(matches!(
        explicitly_correlated_manifest(vec![first, duplicate_backing_identity]),
        Err(SessionManifestError::DuplicateBackingIdentity)
    ));
}

#[test]
fn placement_policy_and_manifest_debug_are_redacted() {
    let correlated_manifest = explicitly_correlated_manifest(vec![
        descriptor(1, "secret-failure-domain"),
        descriptor(2, "secret-failure-domain"),
        descriptor(3, "other-failure-domain"),
    ])
    .expect("explicit correlated placement is admitted");
    let rendered = format!(
        "{correlated_manifest:?} {:?} {:?}",
        correlated_manifest.placement_policy(),
        correlated_manifest.placement_disposition()
    );

    for private_value in [
        "placement-policy-cluster",
        "placement-policy-generation",
        "replica-1.session.invalid",
        "spiffe://test.example",
        "secret-failure-domain",
        "backing-1",
    ] {
        assert!(
            !rendered.contains(private_value),
            "rendered {private_value}"
        );
    }

    let error = manifest(vec![
        descriptor(1, "secret-failure-domain"),
        descriptor(2, "secret-failure-domain"),
    ])
    .expect_err("strict placement must fail");
    let rendered_error = format!("{error:?} {error}");
    assert!(!rendered_error.contains("secret-failure-domain"));
}
