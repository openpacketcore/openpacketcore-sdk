use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use opc_session_store::{
    BackendCapabilities, BackendInstanceIdentity, BackendPeerBinding, BackendPeerBindingField,
    BackendPeerScopeIdentity, CompareAndSet, CompareAndSetResult, FakeSessionBackend,
    FencedSessionReplica, LeaseError, LeaseGuard, OwnerId, QuorumReplicaDescriptor,
    QuorumReplicaMember, QuorumSessionStore, QuorumTopologyConfig, QuorumTopologyError,
    QuorumTopologyMode, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId,
    ReplicaTlsIdentity, ReplicaTopologyField, ReplicaTopologyFieldError, SessionBackend,
    SessionKey, SessionKeyType, SessionLeaseManager, SessionOp, SessionOpResult, SessionStore,
    SessionStoreBackend, SessionStorePlatformProfile, StoreError, StoredSessionRecord,
    ValidatedQuorumTopology, QUORUM_TOPOLOGY_MAX_MEMBERS,
};
use opc_types::{NetworkFunctionKind, TenantId};
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

fn member_with_backend(index: usize, backend: Arc<dyn SessionStoreBackend>) -> QuorumReplicaMember {
    QuorumReplicaMember::new(
        descriptor(replica_id(index), index, index, index, index),
        FencedSessionReplica::new(index, backend),
    )
}

fn member(index: usize) -> QuorumReplicaMember {
    member_with_backend(index, Arc::new(FakeSessionBackend::new()))
}

fn members(count: usize) -> Vec<QuorumReplicaMember> {
    (0..count).map(member).collect()
}

fn validate_ha(
    local_replica_id: ReplicaId,
    members: Vec<QuorumReplicaMember>,
) -> Result<ValidatedQuorumTopology, QuorumTopologyError> {
    ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new(local_replica_id, members))
}

#[derive(Clone)]
struct PeerBoundBackend {
    inner: FakeSessionBackend,
    binding: BackendPeerBinding,
}

impl PeerBoundBackend {
    fn new(binding: BackendPeerBinding) -> Self {
        Self {
            inner: FakeSessionBackend::new(),
            binding,
        }
    }
}

#[async_trait::async_trait]
impl SessionBackend for PeerBoundBackend {
    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        self.inner.backend_instance_identity()
    }

    fn peer_binding(&self) -> Option<BackendPeerBinding> {
        Some(self.binding.clone())
    }

    async fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities().await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        self.inner.get(key).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        self.inner.compare_and_set(op).await
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        self.inner.delete_fenced(lease).await
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        self.inner.refresh_ttl(lease, ttl).await
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        self.inner.batch(ops).await
    }
}

#[async_trait::async_trait]
impl SessionLeaseManager for PeerBoundBackend {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        self.inner.acquire(key, owner, ttl).await
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        self.inner.renew(lease, ttl).await
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        self.inner.release(lease).await
    }
}

fn test_descriptors() -> Vec<QuorumReplicaDescriptor> {
    (0..3)
        .map(|index| descriptor(replica_id(index), index, index, index, index))
        .collect()
}

fn valid_peer_binding(
    descriptors: &[QuorumReplicaDescriptor],
    remote_index: usize,
    scope: BackendPeerScopeIdentity,
) -> BackendPeerBinding {
    BackendPeerBinding::new(
        descriptors[0].replica_id().clone(),
        descriptors[remote_index].replica_id().clone(),
        descriptors[remote_index].tls_identity().clone(),
        descriptors[0].configuration_fingerprint(),
        descriptors[remote_index].configuration_fingerprint(),
        3,
        scope,
    )
}

fn members_with_peer_bindings(
    descriptors: &[QuorumReplicaDescriptor],
    bindings: Vec<Option<BackendPeerBinding>>,
) -> Vec<QuorumReplicaMember> {
    descriptors
        .iter()
        .cloned()
        .zip(bindings)
        .enumerate()
        .map(|(index, (descriptor, binding))| {
            let backend: Arc<dyn SessionStoreBackend> = match binding {
                Some(binding) => Arc::new(PeerBoundBackend::new(binding)),
                None => Arc::new(FakeSessionBackend::new()),
            };
            QuorumReplicaMember::new(descriptor, FencedSessionReplica::new(index, backend))
        })
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
fn authenticated_peer_bindings_admit_with_an_unbound_in_process_local_member() {
    let descriptors = test_descriptors();
    let scope = BackendPeerScopeIdentity::new([7; 32]);
    let bindings = vec![
        None,
        Some(valid_peer_binding(&descriptors, 1, scope)),
        Some(valid_peer_binding(&descriptors, 2, scope)),
    ];

    let topology = validate_ha(
        descriptors[0].replica_id().clone(),
        members_with_peer_bindings(&descriptors, bindings),
    )
    .expect("matching peer bindings must pass topology admission");
    assert_eq!(topology.summary().configured_members(), 3);
}

#[test]
fn one_peer_binding_requires_composition_evidence_for_every_remote_member() {
    let descriptors = test_descriptors();
    let scope = BackendPeerScopeIdentity::new([7; 32]);
    let bindings = vec![None, Some(valid_peer_binding(&descriptors, 1, scope)), None];

    assert_eq!(
        validate_ha(
            descriptors[0].replica_id().clone(),
            members_with_peer_bindings(&descriptors, bindings),
        )
        .err(),
        Some(QuorumTopologyError::MissingBackendPeerBinding)
    );
}

#[test]
fn peer_binding_mismatch_categories_are_typed_and_redacted() {
    let descriptors = test_descriptors();
    let scope = BackendPeerScopeIdentity::new([7; 32]);
    let alternate_scope = BackendPeerScopeIdentity::new([8; 32]);
    let local_fingerprint = descriptors[0].configuration_fingerprint();
    let remote_fingerprint = descriptors[1].configuration_fingerprint();
    let valid_second = valid_peer_binding(&descriptors, 2, scope);
    let build = |local_id: ReplicaId,
                 remote_id: ReplicaId,
                 tls_identity: ReplicaTlsIdentity,
                 local_descriptor_fingerprint: [u8; 32],
                 remote_descriptor_fingerprint: [u8; 32],
                 configured_member_count: u16,
                 binding_scope: BackendPeerScopeIdentity| {
        BackendPeerBinding::new(
            local_id,
            remote_id,
            tls_identity,
            local_descriptor_fingerprint,
            remote_descriptor_fingerprint,
            configured_member_count,
            binding_scope,
        )
    };
    let cases = vec![
        (
            build(
                replica_id(9),
                descriptors[1].replica_id().clone(),
                descriptors[1].tls_identity().clone(),
                local_fingerprint,
                remote_fingerprint,
                3,
                scope,
            ),
            BackendPeerBindingField::LocalReplicaId,
        ),
        (
            build(
                descriptors[0].replica_id().clone(),
                replica_id(9),
                descriptors[1].tls_identity().clone(),
                local_fingerprint,
                remote_fingerprint,
                3,
                scope,
            ),
            BackendPeerBindingField::RemoteReplicaId,
        ),
        (
            build(
                descriptors[0].replica_id().clone(),
                descriptors[1].replica_id().clone(),
                ReplicaTlsIdentity::new("spiffe://private/wrong-peer").expect("wrong TLS ID"),
                local_fingerprint,
                remote_fingerprint,
                3,
                scope,
            ),
            BackendPeerBindingField::RemoteTlsIdentity,
        ),
        (
            build(
                descriptors[0].replica_id().clone(),
                descriptors[1].replica_id().clone(),
                descriptors[1].tls_identity().clone(),
                [1; 32],
                remote_fingerprint,
                3,
                scope,
            ),
            BackendPeerBindingField::LocalDescriptorFingerprint,
        ),
        (
            build(
                descriptors[0].replica_id().clone(),
                descriptors[1].replica_id().clone(),
                descriptors[1].tls_identity().clone(),
                local_fingerprint,
                [2; 32],
                3,
                scope,
            ),
            BackendPeerBindingField::RemoteDescriptorFingerprint,
        ),
        (
            build(
                descriptors[0].replica_id().clone(),
                descriptors[1].replica_id().clone(),
                descriptors[1].tls_identity().clone(),
                local_fingerprint,
                remote_fingerprint,
                5,
                scope,
            ),
            BackendPeerBindingField::ConfiguredMemberCount,
        ),
        (
            build(
                descriptors[0].replica_id().clone(),
                descriptors[1].replica_id().clone(),
                descriptors[1].tls_identity().clone(),
                local_fingerprint,
                remote_fingerprint,
                3,
                alternate_scope,
            ),
            BackendPeerBindingField::Scope,
        ),
    ];

    for (first_binding, field) in cases {
        let debug = format!("{first_binding:?}");
        assert!(!debug.contains("private"));
        let error = validate_ha(
            descriptors[0].replica_id().clone(),
            members_with_peer_bindings(
                &descriptors,
                vec![None, Some(first_binding), Some(valid_second.clone())],
            ),
        )
        .err()
        .expect("mismatched peer binding must fail topology admission");
        assert_eq!(
            error,
            QuorumTopologyError::BackendPeerBindingMismatch { field }
        );
        assert!(!error.to_string().contains("spiffe://"));
    }
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
    let local = QuorumReplicaMember::new(
        QuorumReplicaDescriptor::new(
            bare_self.clone(),
            ReplicaEndpoint::new(
                "epdg-app-0.epdg-app-quorum.epdg-gateway.svc.cluster.local",
                7443,
            )
            .expect("local FQDN endpoint"),
            ReplicaTlsIdentity::new("spiffe://cluster/epdg/replica/0").expect("local TLS identity"),
            ReplicaFailureDomain::new("pod/epdg-app-0").expect("local failure domain"),
            ReplicaBackingIdentity::new("pvc/session-store-0").expect("local backing"),
        ),
        FencedSessionReplica::new(0, Arc::new(FakeSessionBackend::new())),
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
        .find(|member| member.descriptor().replica_id() == &bare_self)
        .expect("validated local member");
    assert_eq!(
        local_member.descriptor().endpoint().host(),
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
    let ambiguous = vec![
        member(0),
        QuorumReplicaMember::new(
            descriptor(local.clone(), 1, 1, 1, 1),
            FencedSessionReplica::new(1, Arc::new(FakeSessionBackend::new())),
        ),
        member(2),
    ];
    assert_eq!(
        validate_ha(local, ambiguous).err(),
        Some(QuorumTopologyError::AmbiguousLocalReplica { matches: 2 })
    );
}

#[test]
fn every_vote_identity_dimension_must_be_distinct() {
    let cases = [
        (
            vec![
                member(0),
                member(1),
                QuorumReplicaMember::new(
                    descriptor(replica_id(1), 2, 2, 2, 2),
                    FencedSessionReplica::new(2, Arc::new(FakeSessionBackend::new())),
                ),
            ],
            QuorumTopologyError::DuplicateReplicaId,
        ),
        (
            vec![
                member(0),
                member(1),
                QuorumReplicaMember::new(
                    descriptor(replica_id(2), 1, 2, 2, 2),
                    FencedSessionReplica::new(2, Arc::new(FakeSessionBackend::new())),
                ),
            ],
            QuorumTopologyError::DuplicateEndpoint,
        ),
        (
            vec![
                member(0),
                member(1),
                QuorumReplicaMember::new(
                    descriptor(replica_id(2), 2, 1, 2, 2),
                    FencedSessionReplica::new(2, Arc::new(FakeSessionBackend::new())),
                ),
            ],
            QuorumTopologyError::DuplicateTlsIdentity,
        ),
        (
            vec![
                member(0),
                member(1),
                QuorumReplicaMember::new(
                    descriptor(replica_id(2), 2, 2, 1, 2),
                    FencedSessionReplica::new(2, Arc::new(FakeSessionBackend::new())),
                ),
            ],
            QuorumTopologyError::DuplicateFailureDomain,
        ),
        (
            vec![
                member(0),
                member(1),
                QuorumReplicaMember::new(
                    descriptor(replica_id(2), 2, 2, 2, 1),
                    FencedSessionReplica::new(2, Arc::new(FakeSessionBackend::new())),
                ),
            ],
            QuorumTopologyError::DuplicateBackingIdentity,
        ),
    ];

    for (members, expected) in cases {
        assert_eq!(validate_ha(replica_id(0), members).err(), Some(expected));
    }
}

#[test]
fn dns_case_and_trailing_dot_cannot_alias_two_endpoint_votes() {
    let first = QuorumReplicaMember::new(
        QuorumReplicaDescriptor::new(
            replica_id(1),
            ReplicaEndpoint::new("PEER.SESSIONS.TEST.INVALID.", 7443)
                .expect("absolute uppercase endpoint"),
            ReplicaTlsIdentity::new("spiffe://test/session/replica/1").expect("TLS identity"),
            ReplicaFailureDomain::new("test-failure-domain-1").expect("failure domain"),
            ReplicaBackingIdentity::new("test-backing-1").expect("backing identity"),
        ),
        FencedSessionReplica::new(1, Arc::new(FakeSessionBackend::new())),
    );
    let alias = QuorumReplicaMember::new(
        QuorumReplicaDescriptor::new(
            replica_id(2),
            ReplicaEndpoint::new("peer.sessions.test.invalid", 7443).expect("lowercase endpoint"),
            ReplicaTlsIdentity::new("spiffe://test/session/replica/2").expect("TLS identity"),
            ReplicaFailureDomain::new("test-failure-domain-2").expect("failure domain"),
            ReplicaBackingIdentity::new("test-backing-2").expect("backing identity"),
        ),
        FencedSessionReplica::new(2, Arc::new(FakeSessionBackend::new())),
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
fn one_backend_wrapped_as_three_votes_is_rejected() {
    let backend: Arc<dyn SessionStoreBackend> = Arc::new(FakeSessionBackend::new());
    let aliased = (0..3)
        .map(|index| member_with_backend(index, backend.clone()))
        .collect();

    assert_eq!(
        validate_ha(replica_id(0), aliased).err(),
        Some(QuorumTopologyError::DuplicateBackendInstance)
    );
}

#[test]
fn distinct_sdk_wrappers_around_one_backend_cannot_create_three_votes() {
    let shared = Arc::new(FakeSessionBackend::new());
    let wrapped = (0..3)
        .map(|index| {
            let backend: Arc<dyn SessionStoreBackend> =
                Arc::new(SessionStore::from_arc(shared.clone()));
            member_with_backend(index, backend)
        })
        .collect();

    assert_eq!(
        validate_ha(replica_id(0), wrapped).err(),
        Some(QuorumTopologyError::DuplicateBackendInstance)
    );
}

#[test]
fn nested_quorum_coordinators_cannot_be_admitted_as_replica_votes() {
    let coordinator = QuorumSessionStore::from_validated_topology(
        validate_ha(replica_id(0), members(3)).expect("inner validated topology"),
    );
    assert!(coordinator.backend_instance_identity().is_none());

    let nested = (0..3)
        .map(|index| {
            let backend: Arc<dyn SessionStoreBackend> = Arc::new(coordinator.clone());
            member_with_backend(index, backend)
        })
        .collect();
    assert_eq!(
        validate_ha(replica_id(0), nested).err(),
        Some(QuorumTopologyError::MissingBackendInstanceIdentity)
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
fn lab_singleton_is_operational_but_never_advertises_ha() {
    let local = replica_id(0);
    let topology = ValidatedQuorumTopology::try_new_lab_singleton(local.clone(), vec![member(0)])
        .expect("explicit singleton");
    let store = QuorumSessionStore::from_validated_topology(topology);

    assert_eq!(store.topology().mode(), QuorumTopologyMode::LabSingleton);
    assert_eq!(store.topology().required_quorum(), 1);
    assert_eq!(
        store.platform_profile(),
        SessionStorePlatformProfile::SingleReplica
    );
    assert_eq!(store.topology().local_replica_id(), Some(&local));

    assert_eq!(
        ValidatedQuorumTopology::try_new_lab_singleton(replica_id(0), Vec::new()).err(),
        Some(QuorumTopologyError::LabMemberCount { configured: 0 })
    );
    assert_eq!(
        ValidatedQuorumTopology::try_new_lab_singleton(replica_id(0), members(2)).err(),
        Some(QuorumTopologyError::LabMemberCount { configured: 2 })
    );
}

#[test]
fn mapping_backends_revalidates_allocation_distinctness() {
    let topology = validate_ha(replica_id(0), members(3)).expect("valid topology");
    let alias: Arc<dyn SessionStoreBackend> = Arc::new(FakeSessionBackend::new());
    let error = topology
        .try_map_backends(|_, _| alias.clone())
        .err()
        .expect("mapped aliases must fail");
    assert_eq!(error, QuorumTopologyError::DuplicateBackendInstance);
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

#[tokio::test]
#[allow(deprecated)]
async fn deprecated_raw_constructor_is_non_operational_and_non_ha() {
    let backend = Arc::new(FakeSessionBackend::new());
    let key = SessionKey {
        tenant: TenantId::new("tenant-a").expect("tenant"),
        nf_kind: NetworkFunctionKind::from_static("epdg"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(b"legacy-topology"),
    };
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("fixture lease");
    let store = QuorumSessionStore::new(vec![
        FencedSessionReplica::new(0, backend),
        FencedSessionReplica::new(1, Arc::new(FakeSessionBackend::new())),
        FencedSessionReplica::new(2, Arc::new(FakeSessionBackend::new())),
    ]);

    assert_eq!(
        store.topology().mode(),
        QuorumTopologyMode::UnvalidatedLegacy
    );
    assert_eq!(
        store.platform_profile(),
        SessionStorePlatformProfile::Unknown
    );
    assert!(!store.capabilities().await.restore_scan);
    assert_eq!(
        store.max_replication_sequence().await,
        Err(StoreError::BackendUnavailable(
            "session-store topology is not validated".into()
        ))
    );
    assert_eq!(
        store.batch(Vec::new()).await,
        Err(StoreError::BackendUnavailable(
            "session-store topology is not validated".into()
        ))
    );
    assert_eq!(
        store.refresh_ttl(&lease, Duration::MAX).await,
        Err(StoreError::InvalidSessionTtl)
    );
    assert_eq!(
        store.refresh_ttl(&lease, Duration::from_secs(60)).await,
        Err(StoreError::BackendUnavailable(
            "session-store topology is not validated".into()
        ))
    );
    assert_eq!(
        store.renew(&lease, Duration::MAX).await,
        Err(LeaseError::InvalidSessionTtl)
    );
    assert_eq!(
        store.renew(&lease, Duration::from_secs(60)).await,
        Err(LeaseError::Backend(
            "backend unavailable: session-store topology is not validated".into()
        ))
    );
    assert_eq!(
        store
            .acquire(&key, OwnerId::new("owner-b").expect("owner"), Duration::MAX,)
            .await,
        Err(LeaseError::InvalidSessionTtl)
    );
    assert_eq!(
        store
            .acquire(
                &key,
                OwnerId::new("owner-b").expect("owner"),
                Duration::from_secs(60),
            )
            .await,
        Err(LeaseError::Backend(
            "backend unavailable: session-store topology is not validated".into()
        ))
    );
}
