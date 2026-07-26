//! Public composition proof for the destination-scoped first-activation
//! boundary (issue #561).
//!
//! Everything here uses only the crate's public API. The steering side is a
//! test-owned implementation of the public `RePinSteeringBackend` /
//! `RePinSteeringRetirementBackend` ports holding the same two maps the
//! Host-XDP datapath owns (`IPSEC_LB_OWNERS` and `IPSEC_LB_KEY_FENCES`), so the
//! owner-shard/generation readback and the post-retirement absence proofs are
//! real observations rather than assertions about a mock's call log. The
//! `HostXdpSteeringBackend` type itself is composed alongside it to prove the
//! production backend satisfies the same bounds; its kernel map cannot be
//! observed without a privileged netns, and its runtime injection point is
//! deliberately not public.
//!
//! The re-pin leg uses an IKE SA with random-IV resume evidence because
//! counter-based ESP re-pin additionally requires an opaque XFRM apply receipt
//! that only production can mint.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use opc_ipsec_lb::ownership::{
    DestinationContext, EstablishedIkeOwnershipKey, IkeSpi, RoutingDomainTag,
};
use opc_ipsec_lb::{
    AntiReplayResume, ClusterNode, HostXdpSteeringBackend, HostXdpSteeringBackendConfig,
    IkeRandomIvAttestation, IpAddress, IpsecLbError, MockRePinAuditSink,
    OwnershipActivationRequest, OwnershipActivationRetirement, OwnershipFence,
    OwnershipRetirementFinalization, OwnershipRetirementGrant, OwnershipTransitionId,
    RePinCoordinator, RePinRequest, RePinSteeringBackend, RePinSteeringOperationPermit,
    RePinSteeringRetirementBackend, RePinSteeringUpdate, ResumeKeySource, SameSpiOutboundIvResume,
    SameSpiResume, SessionOwnershipKey, SessionOwnershipKeyResolver, SessionOwnershipKeyspace,
    SessionStoreOwnershipFencer, SessionStoreOwnershipSource, ShardId, SteerKey, SteeringRule,
};
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, FakeSessionBackend, Generation,
    OwnerId, SessionBackend, SessionKey, SessionLeaseManager, StateClass, StateType,
    StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId};

const ROUTING_DOMAIN: u64 = 7;
const RESPONDER_SPI: u64 = 0x0561_0000_0000_0011;
const INITIATOR_SPI: u64 = 0x0561_0000_0000_0022;

/// Datapath mirror holding exactly the two destination-scoped maps the XDP
/// program reads, with the same fence-last activation and fence-first
/// retirement ordering the Host backend implements.
///
/// Cloning shares the maps, so a test can retain an observation handle while
/// the coordinator owns its copy.
#[derive(Debug, Clone, Default)]
struct MirrorSteeringBackend {
    state: Arc<Mutex<MirrorState>>,
    /// Fail `retire_fenced_repin`, modelling a transient datapath error that
    /// lands *after* the durable `Retiring` CAS has already committed.
    fail_retirement: Arc<AtomicBool>,
}

#[derive(Debug, Default)]
struct MirrorState {
    owners: BTreeMap<SessionOwnershipKey, (ShardId, u64)>,
    key_fences: BTreeMap<SessionOwnershipKey, u64>,
}

impl MirrorSteeringBackend {
    fn owner_record(&self, key: &SessionOwnershipKey) -> Option<(ShardId, u64)> {
        self.lock().owners.get(key).copied()
    }

    fn key_fence(&self, key: &SessionOwnershipKey) -> Option<u64> {
        self.lock().key_fences.get(key).copied()
    }

    fn fail_retirement(&self, fail: bool) {
        self.fail_retirement.store(fail, Ordering::SeqCst);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MirrorState> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

#[async_trait]
impl RePinSteeringBackend for MirrorSteeringBackend {
    async fn apply_fenced_repin(
        &self,
        update: RePinSteeringUpdate,
        permit: RePinSteeringOperationPermit,
    ) -> Result<RePinSteeringOperationPermit, IpsecLbError> {
        if permit.ownership_key() != update.ownership_key() {
            return Err(IpsecLbError::adapter_contract_violation(
                "mirror_permit_key_mismatch",
            ));
        }
        let key = update.ownership_key();
        let generation = update.generation().get();
        let mut state = self.lock();
        if state
            .key_fences
            .get(&key)
            .is_some_and(|fence| *fence > generation)
            || state
                .owners
                .get(&key)
                .is_some_and(|(_, observed)| *observed > generation)
        {
            return Err(IpsecLbError::ownership_conflict(
                "destination-scoped owner or fence generation cannot regress",
            ));
        }
        // Fence-last: withdraw the fence, stage the owner while the entry is
        // stale, then publish the fence as the activation point.
        state.key_fences.remove(&key);
        state.owners.insert(key, (update.owner(), generation));
        state.key_fences.insert(key, generation);
        Ok(permit)
    }
}

#[async_trait]
impl RePinSteeringRetirementBackend for MirrorSteeringBackend {
    async fn acquire_repin_retirement_permits(
        &self,
        ownership_keys: Vec<SessionOwnershipKey>,
    ) -> Result<Vec<RePinSteeringOperationPermit>, IpsecLbError> {
        // The public port has no permit constructor, so round-trip through the
        // default activation permit the trait itself hands out.
        let mut permits = Vec::with_capacity(ownership_keys.len());
        for key in ownership_keys {
            permits.push(self.acquire_repin_permit(key).await?);
        }
        Ok(permits)
    }

    fn arm_repin_retirement_permit(
        &self,
        permit: RePinSteeringOperationPermit,
    ) -> Result<RePinSteeringOperationPermit, IpsecLbError> {
        Ok(permit)
    }

    fn release_classified_repin_retirement_permit(
        &self,
        _permit: RePinSteeringOperationPermit,
    ) -> Result<(), IpsecLbError> {
        Ok(())
    }

    async fn retire_fenced_repin(
        &self,
        grant: &OwnershipRetirementGrant,
        permit: RePinSteeringOperationPermit,
    ) -> Result<RePinSteeringOperationPermit, IpsecLbError> {
        let request = grant.request();
        let key = request.ownership_key();
        if permit.ownership_key() != key {
            return Err(IpsecLbError::adapter_contract_violation(
                "mirror_permit_key_mismatch",
            ));
        }
        if self.fail_retirement.load(Ordering::SeqCst) {
            return Err(IpsecLbError::adapter_contract_violation(
                "mirror_injected_retirement_failure",
            ));
        }
        if grant.retirement_fence().get() <= request.active_fence().get() {
            return Err(IpsecLbError::adapter_contract_violation(
                "mirror_retirement_fence_did_not_advance",
            ));
        }
        let mut state = self.lock();
        if let Some((owner, generation)) = state.owners.get(&key).copied() {
            if owner != request.map_owner() || generation != request.active_fence().get() {
                return Err(IpsecLbError::ownership_conflict(
                    "retirement found a foreign destination-scoped owner",
                ));
            }
        }
        // Higher fence first as the fail-closed cut, then remove both entries.
        state.key_fences.insert(key, grant.retirement_fence().get());
        state.owners.remove(&key);
        state.key_fences.remove(&key);
        Ok(permit)
    }
}

fn keyspace() -> SessionOwnershipKeyspace {
    SessionOwnershipKeyspace::new(
        TenantId::new("tenant-a").expect("valid tenant"),
        NetworkFunctionKind::new("epdg").expect("valid NF kind"),
    )
}

fn ownership_key() -> SessionOwnershipKey {
    SessionOwnershipKey::EstablishedIke(EstablishedIkeOwnershipKey::new(
        DestinationContext::new(
            IpAddress::V4([203, 0, 113, 7]),
            RoutingDomainTag::new(ROUTING_DOMAIN),
        ),
        IkeSpi::new(INITIATOR_SPI).expect("nonzero initiator SPI"),
        IkeSpi::new(RESPONDER_SPI).expect("nonzero responder SPI"),
    ))
}

fn rule(owner: ShardId) -> SteeringRule {
    SteeringRule {
        shard: ShardId::new(7),
        owner,
        key: SteerKey::IkeResponderSpi(RESPONDER_SPI),
    }
}

/// Create the authoritative birth record the SA birth path owns.
///
/// This is the only thing a caller has to do before activation, and it is done
/// exactly as the README documents it: resolve the key with the public
/// resolver, take a lease, build the record with
/// `SessionStoreOwnershipFencer::birth_record`, then CAS with
/// `expected_generation: None`. Nothing here names the crate's private
/// ownership state type — a caller cannot, which is precisely why the helper
/// exists.
async fn write_birth_record(
    store: &FakeSessionBackend,
    key: SessionKey,
    owner: &str,
) -> StoredSessionRecord {
    let fencer = SessionStoreOwnershipFencer::new(store.clone(), keyspace());
    let lease = store
        .acquire(
            &key,
            OwnerId::new(owner).expect("valid owner"),
            Duration::from_secs(60),
        )
        .await
        .expect("birth lease");
    let record = fencer
        .birth_record(&key, &ClusterNode::new(owner), &lease)
        .expect("birth record");
    assert_eq!(record.state_class, StateClass::AuthoritativeSession);
    assert_eq!(record.generation, Generation::new(1));
    assert_eq!(
        store
            .compare_and_set(CompareAndSet {
                key,
                lease: lease.clone(),
                expected_generation: None,
                new_record: record.clone(),
            })
            .await
            .expect("birth CAS"),
        CompareAndSetResult::Success
    );
    store.release(lease).await.expect("birth lease release");
    record
}

/// A hand-rolled record following the README's *old* step 1 literally — an
/// authoritative record with no ownership state type — is refused, which is the
/// failure `birth_record` exists to prevent.
#[tokio::test]
async fn a_birth_record_without_the_ownership_state_type_fails_closed() {
    let store = FakeSessionBackend::new();
    let key = ownership_key();
    let scoped = keyspace().scoped_sa_key(&key).expect("scoped SA key");

    seed_shard_owner(&store, ShardId::new(3), "owner-a").await;

    let owner = OwnerId::new("owner-a").expect("valid owner");
    let lease = store
        .acquire(&scoped, owner.clone(), Duration::from_secs(60))
        .await
        .expect("birth lease");
    let hand_rolled = StoredSessionRecord {
        key: scoped.clone(),
        generation: Generation::new(1),
        owner,
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("ipsec-lb-sa"),
        expires_at: None,
        payload: EncryptedSessionPayload::new([]),
    };
    assert_eq!(
        store
            .compare_and_set(CompareAndSet {
                key: scoped,
                lease: lease.clone(),
                expected_generation: None,
                new_record: hand_rolled,
            })
            .await
            .expect("birth CAS"),
        CompareAndSetResult::Success
    );
    store.release(lease).await.expect("birth lease release");

    let (coordinator, steering) = coordinator(&store);
    assert_eq!(
        coordinator
            .activate(&activation_request(0x5610_0009, "owner-a", ShardId::new(3)))
            .await,
        Err(IpsecLbError::invalid_config(
            "session_store.state_type",
            "ownership record state type mismatch",
        ))
    );
    assert_eq!(steering.owner_record(&key), None);
}

async fn seed_shard_owner(store: &FakeSessionBackend, shard: ShardId, owner: &str) {
    let key = keyspace().shard_key(shard).expect("shard key");
    write_birth_record(store, key, owner).await;
}

fn activation_request(transition: u128, owner: &str, shard: ShardId) -> OwnershipActivationRequest {
    OwnershipActivationRequest::new_ike(
        RESPONDER_SPI,
        OwnershipTransitionId::new(transition).expect("nonzero transition"),
        ClusterNode::new(owner),
        rule(shard),
        ownership_key(),
    )
    .expect("valid activation request")
}

type Coordinator = RePinCoordinator<
    MirrorSteeringBackend,
    SessionStoreOwnershipFencer<FakeSessionBackend>,
    SessionStoreOwnershipSource<FakeSessionBackend>,
    MockRePinAuditSink,
>;

fn coordinator(store: &FakeSessionBackend) -> (Coordinator, MirrorSteeringBackend) {
    let steering = MirrorSteeringBackend::default();
    let coordinator = RePinCoordinator::new(
        steering.clone(),
        SessionStoreOwnershipFencer::new(store.clone(), keyspace()),
        SessionStoreOwnershipSource::new(store.clone(), keyspace()),
        MockRePinAuditSink::new(),
    );
    (coordinator, steering)
}

#[tokio::test]
async fn public_first_activation_then_repin_needs_no_placeholder_predecessor() {
    let store = FakeSessionBackend::new();
    let key = ownership_key();
    let scoped = keyspace().scoped_sa_key(&key).expect("scoped SA key");

    seed_shard_owner(&store, ShardId::new(3), "owner-a").await;
    seed_shard_owner(&store, ShardId::new(5), "owner-b").await;
    write_birth_record(&store, scoped, "owner-a").await;

    let (coordinator, steering) = coordinator(&store);
    let activation = activation_request(0x5610_0001, "owner-a", ShardId::new(3));

    // 1. First publication for a key that has never had an owner record. No
    //    predecessor owner, no predecessor fence, no resume evidence.
    let activated = coordinator
        .activate(&activation)
        .await
        .expect("first activation publishes");
    assert_eq!(
        steering.owner_record(&key),
        Some((ShardId::new(3), activated.fence().get())),
        "the exact owner shard and generation must be readable"
    );
    assert_eq!(steering.key_fence(&key), Some(activated.fence().get()));

    // 2. Re-pin the same key through the ordinary coordinator, binding the
    //    activation's own fence as the predecessor. No legacy SPI-only rule and
    //    no placeholder predecessor owner are involved.
    let repin = RePinRequest::new_ike(
        RESPONDER_SPI,
        OwnershipTransitionId::new(0x5610_0002).expect("nonzero transition"),
        activated.fence(),
        ClusterNode::new("owner-a"),
        ClusterNode::new("owner-b"),
        rule(ShardId::new(5)),
        key,
        SameSpiResume {
            previous_sa: activation.sa(),
            resumed_sa: activation.sa(),
            outbound_iv: SameSpiOutboundIvResume::IkeRandomIv {
                attestation: IkeRandomIvAttestation::FreshIndependentCsprngIvPerMessage,
            },
            anti_replay: AntiReplayResume::ExactWindowRestore {
                checkpoint_highest_accepted: 41,
                restored_highest_accepted: 41,
            },
            key_source: ResumeKeySource::LiveMirrored,
        },
    )
    .expect("valid re-pin request");

    let repinned = coordinator.repin(repin).await.expect("re-pin succeeds");
    assert!(repinned.fence() > activated.fence());
    assert_eq!(
        steering.owner_record(&key),
        Some((ShardId::new(5), repinned.fence().get()))
    );
    assert_eq!(steering.key_fence(&key), Some(repinned.fence().get()));
}

#[tokio::test]
async fn public_activation_retires_and_leaves_both_maps_absent() {
    let store = FakeSessionBackend::new();
    let key = ownership_key();
    let scoped = keyspace().scoped_sa_key(&key).expect("scoped SA key");

    seed_shard_owner(&store, ShardId::new(3), "owner-a").await;
    write_birth_record(&store, scoped.clone(), "owner-a").await;

    let (coordinator, steering) = coordinator(&store);
    let activation = activation_request(0x5610_0003, "owner-a", ShardId::new(3));
    let activated = coordinator
        .activate(&activation)
        .await
        .expect("first activation publishes");
    assert_eq!(
        steering.owner_record(&key),
        Some((ShardId::new(3), activated.fence().get()))
    );

    // Retirement for an activation that never underwent a re-pin.
    let retirement = coordinator
        .retire_activation(&activation, activated.fence())
        .await
        .expect("activation retires");
    match retirement {
        OwnershipActivationRetirement::Finalized(proof) => assert_eq!(
            proof.disposition(),
            OwnershipRetirementFinalization::Deleted
        ),
        OwnershipActivationRetirement::Superseded(_) => {
            panic!("a freshly activated key cannot be superseded")
        }
    }

    assert_eq!(steering.owner_record(&key), None, "owner map must be empty");
    assert_eq!(steering.key_fence(&key), None, "fence map must be empty");
    assert!(
        store.get(&scoped).await.expect("read").is_none(),
        "durable ownership record must be deleted"
    );
}

/// HIGH-1 at the public boundary: after a completed retirement both datapath
/// maps and the store record are empty, which is indistinguishable from "never
/// activated". Replaying the exact activation must still be refused, and any
/// genuine rebirth must land strictly above the retirement fence.
#[tokio::test]
async fn public_retired_key_cannot_be_reactivated_below_its_retirement_fence() {
    let store = FakeSessionBackend::new();
    let key = ownership_key();
    let scoped = keyspace().scoped_sa_key(&key).expect("scoped SA key");

    seed_shard_owner(&store, ShardId::new(3), "owner-a").await;
    write_birth_record(&store, scoped.clone(), "owner-a").await;

    let (coordinator, steering) = coordinator(&store);
    let activation = activation_request(0x5610_0004, "owner-a", ShardId::new(3));
    let activated = coordinator.activate(&activation).await.expect("activates");
    coordinator
        .retire_activation(&activation, activated.fence())
        .await
        .expect("activation retires");

    assert_eq!(steering.owner_record(&key), None);
    assert_eq!(steering.key_fence(&key), None);

    // Both maps empty and the record deleted must not read as "never used".
    assert_eq!(
        coordinator.activate(&activation).await,
        Err(IpsecLbError::NotFound)
    );

    // A genuine rebirth is admitted and is strictly above the retired fence,
    // because the store retained this key's durable fence floor across the
    // fenced delete.
    let rebirth = write_birth_record(&store, scoped, "owner-a").await;
    assert!(rebirth.fence.get() > activated.fence().get());
    let successor = activation_request(0x5610_0005, "owner-a", ShardId::new(3));
    let reactivated = coordinator
        .activate(&successor)
        .await
        .expect("rebirth activates");
    assert!(reactivated.fence() > activated.fence());
    assert_eq!(
        steering.owner_record(&key),
        Some((ShardId::new(3), reactivated.fence().get()))
    );
}

#[tokio::test]
async fn public_activation_never_overwrites_a_key_held_by_another_owner() {
    let store = FakeSessionBackend::new();
    let key = ownership_key();
    let scoped = keyspace().scoped_sa_key(&key).expect("scoped SA key");

    seed_shard_owner(&store, ShardId::new(3), "owner-a").await;
    seed_shard_owner(&store, ShardId::new(4), "owner-b").await;
    write_birth_record(&store, scoped, "owner-a").await;

    let (coordinator, steering) = coordinator(&store);
    let owner_a = activation_request(0x5610_0006, "owner-a", ShardId::new(3));
    let activated = coordinator.activate(&owner_a).await.expect("activates");

    let owner_b = activation_request(0x5610_0007, "owner-b", ShardId::new(4));
    assert_eq!(
        coordinator.activate(&owner_b).await,
        Err(IpsecLbError::ownership_conflict(
            "ownership key is already held by a different transition or owner",
        ))
    );
    assert_eq!(
        steering.owner_record(&key),
        Some((ShardId::new(3), activated.fence().get())),
        "the committed owner must survive a rejected claim"
    );
}

#[tokio::test]
async fn public_activation_without_a_birth_record_fails_closed() {
    let store = FakeSessionBackend::new();
    seed_shard_owner(&store, ShardId::new(3), "owner-a").await;
    let (coordinator, steering) = coordinator(&store);
    let activation = activation_request(0x5610_0008, "owner-a", ShardId::new(3));

    assert_eq!(
        coordinator.activate(&activation).await,
        Err(IpsecLbError::NotFound)
    );
    assert_eq!(steering.owner_record(&ownership_key()), None);
}

/// The production Host-XDP backend satisfies the same activation *and*
/// retirement bounds.
///
/// `RePinCoordinator::new` alone does not prove that: its bounds are
/// `RePinSteeringBackend`/`OwnershipFencer`/`OwnershipSource`/`RePinAuditSink`
/// and mention neither `OwnershipActivationAuthority` nor
/// `RePinSteeringRetirementBackend`. The extra bounds live on `activate` and
/// `retire_activation`, so the claim is only true if both are actually called.
/// They are, below. The backend's kernel maps need a privileged netns, so the
/// calls run against the `unsupported` runtime and are expected to fail — what
/// is being proven here is that the composition type-checks, not that it
/// steers.
#[tokio::test]
async fn host_xdp_backend_composes_with_the_activation_boundary() {
    let store = FakeSessionBackend::new();
    seed_shard_owner(&store, ShardId::new(3), "owner-a").await;
    write_birth_record(
        &store,
        keyspace().scoped_sa_key(&ownership_key()).expect("key"),
        "owner-a",
    )
    .await;

    let coordinator: RePinCoordinator<
        HostXdpSteeringBackend,
        SessionStoreOwnershipFencer<FakeSessionBackend>,
        SessionStoreOwnershipSource<FakeSessionBackend>,
        MockRePinAuditSink,
    > = RePinCoordinator::new(
        HostXdpSteeringBackend::unsupported(
            "swu0",
            HostXdpSteeringBackendConfig::default().for_destination_scoped_repin(),
        ),
        SessionStoreOwnershipFencer::new(store.clone(), keyspace()),
        SessionStoreOwnershipSource::new(store, keyspace()),
        MockRePinAuditSink::new(),
    );
    let request = activation_request(0x5610_000a, "owner-a", ShardId::new(3));
    let fence = OwnershipFence::new(4).expect("nonzero fence");

    assert!(
        coordinator.activate(&request).await.is_err(),
        "the unsupported runtime cannot publish, but the bound must hold"
    );
    assert!(
        coordinator
            .retire_activation(&request, fence)
            .await
            .is_err(),
        "the unsupported runtime cannot retire, but the bound must hold"
    );
}

/// SEC-1: a steering failure after the durable `Retiring` CAS strands the key.
/// Recovery must not require the caller to still hold the original request.
#[tokio::test]
async fn a_stranded_retiring_record_is_recoverable_without_the_original_request() {
    let store = FakeSessionBackend::new();
    let key = ownership_key();
    let scoped = keyspace().scoped_sa_key(&key).expect("scoped SA key");

    seed_shard_owner(&store, ShardId::new(3), "owner-a").await;
    write_birth_record(&store, scoped.clone(), "owner-a").await;

    let (coordinator, steering) = coordinator(&store);
    let activation = activation_request(0x5610_000b, "owner-a", ShardId::new(3));
    let activated = coordinator.activate(&activation).await.expect("activates");

    // The retirement's first phase commits `Retiring`, then steering fails.
    steering.fail_retirement(true);
    assert!(coordinator
        .retire_activation(&activation, activated.fence())
        .await
        .is_err());
    steering.fail_retirement(false);

    // The key is now bricked for activation: even a brand-new transition ID is
    // refused, and the datapath entry is still present.
    assert_eq!(
        coordinator
            .activate(&activation_request(0x5610_000c, "owner-a", ShardId::new(3)))
            .await,
        Err(IpsecLbError::ownership_conflict(
            "ownership record is retiring",
        ))
    );

    // Simulate process loss: the original request and fence are gone. Rebuild
    // both from the durable record plus the deployment's own steering rule.
    let fencer = SessionStoreOwnershipFencer::new(store.clone(), keyspace());
    let stranded = fencer
        .recover_stranded_activation_retirement(activation.sa(), key, rule(ShardId::new(3)))
        .await
        .expect("recovery read succeeds")
        .expect("the key is stranded in Retiring");
    assert_eq!(stranded.active_fence(), activated.fence());

    // A wrong steering rule must not be able to retire this key.
    assert_eq!(
        fencer
            .recover_stranded_activation_retirement(activation.sa(), key, rule(ShardId::new(5)))
            .await,
        Err(IpsecLbError::ownership_conflict(
            "recovered activation does not match the retiring ownership record",
        ))
    );

    // Replaying the reconstructed retirement converges the key forward.
    match coordinator
        .retire_activation(stranded.request(), stranded.active_fence())
        .await
        .expect("the reconstructed retirement replays")
    {
        OwnershipActivationRetirement::Finalized(proof) => assert_eq!(
            proof.disposition(),
            OwnershipRetirementFinalization::Deleted
        ),
        OwnershipActivationRetirement::Superseded(_) => {
            panic!("the exact stranded lineage cannot be superseded")
        }
    }
    assert_eq!(steering.owner_record(&key), None);
    assert_eq!(steering.key_fence(&key), None);
    assert!(store.get(&scoped).await.expect("read").is_none());

    // A key that is not stranded reports nothing to recover.
    assert_eq!(
        fencer
            .recover_stranded_activation_retirement(activation.sa(), key, rule(ShardId::new(3)))
            .await,
        Ok(None)
    );
}

/// SEC-2: recovery hands back the original caller's `OwnershipTransitionId` to
/// anyone who can name the SA and its ownership key. That disclosure is inert
/// for exactly one reason — a `Retiring` record's transition is already
/// terminally committed to teardown, so the identity is spent and the only
/// thing it can still do is finish that teardown. This pins the state gate the
/// whole argument rests on: a record that is *not* `Retiring` must disclose
/// nothing.
///
/// The dangerous case is a live `Active` record. Its transition ID is unspent
/// authorization, so reconstructing a request from it would let a third party
/// tear down a working SA using only public protocol values. Generalizing
/// recovery to `Active` looks like a reasonable convenience and is a privilege
/// escalation; this test is what stops it landing silently.
#[tokio::test]
async fn recovery_discloses_no_transition_identity_for_a_non_retiring_record() {
    let store = FakeSessionBackend::new();
    let key = ownership_key();
    let scoped = keyspace().scoped_sa_key(&key).expect("scoped SA key");
    let fencer = SessionStoreOwnershipFencer::new(store.clone(), keyspace());
    let activation = activation_request(0x5610_000d, "owner-a", ShardId::new(3));

    // No record at all: nothing is in flight and nothing exists to disclose.
    assert_eq!(
        fencer
            .recover_stranded_activation_retirement(activation.sa(), key, rule(ShardId::new(3)))
            .await,
        Ok(None),
        "an absent record must not reconstruct a request"
    );

    seed_shard_owner(&store, ShardId::new(3), "owner-a").await;
    write_birth_record(&store, scoped.clone(), "owner-a").await;

    // An unbound birth record has no transition bound to it yet.
    assert_eq!(
        fencer
            .recover_stranded_activation_retirement(activation.sa(), key, rule(ShardId::new(3)))
            .await,
        Ok(None),
        "an unbound birth record must not reconstruct a request"
    );

    // The load-bearing case: a live, activated, not-yet-retiring SA. The
    // reconstruction inputs are all public and all correct here — the SA, the
    // destination-scoped key, and the deployment's real steering rule — so the
    // *only* thing refusing disclosure is the record's state.
    let (coordinator, steering) = coordinator(&store);
    let activated = coordinator.activate(&activation).await.expect("activates");
    assert_eq!(
        steering.owner_record(&key),
        Some((ShardId::new(3), activated.fence().get())),
        "the SA must be live for the disclosure boundary to mean anything"
    );
    assert_eq!(
        fencer
            .recover_stranded_activation_retirement(activation.sa(), key, rule(ShardId::new(3)))
            .await,
        Ok(None),
        "an Active record must never disclose its unspent transition identity"
    );

    // The read is a read: the live SA is untouched and still steering.
    assert_eq!(
        steering.owner_record(&key),
        Some((ShardId::new(3), activated.fence().get()))
    );
    assert_eq!(steering.key_fence(&key), Some(activated.fence().get()));
}
