//! Protocol-neutral, leadership-driven VIP ownership coordination.

use std::num::NonZeroU64;

use crate::error::IpsecLbError;
use crate::model::VipAdvertisement;
use crate::ports::VipAdvertiser;

/// Monotonic, deployment-unique leadership fence token.
///
/// A caller must supply a strictly newer value for every new leadership epoch,
/// including an ABA return to the same node. This token is independent of any
/// IPsec SA, shard, IKE, or ESP identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct LeadershipFence(NonZeroU64);

impl LeadershipFence {
    /// Build a non-zero leadership fence token.
    pub fn new(value: u64) -> Result<Self, IpsecLbError> {
        let Some(value) = NonZeroU64::new(value) else {
            return Err(IpsecLbError::invalid_config(
                "leadership_fence",
                "leadership fence token must be non-zero",
            ));
        };
        Ok(Self(value))
    }

    /// Return the numeric fence value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Caller-supplied evidence that this node may own a VIP.
///
/// The default is fail-closed: it describes a non-leader without quorum,
/// health, or a fence. The signal is deliberately protocol-neutral and must be
/// derived from the caller's own single-writer election and service-health
/// boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VipOwnershipIntent {
    /// This node is the elected owner.
    pub leader: bool,
    /// This node can currently prove quorum liveness.
    pub quorum_available: bool,
    /// This node's northbound listeners are healthy.
    pub healthy: bool,
    /// Fence valid for the current leadership epoch.
    pub fence: Option<LeadershipFence>,
}

impl VipOwnershipIntent {
    const fn has_complete_owner_signal(self) -> bool {
        self.leader && self.quorum_available && self.healthy && self.fence.is_some()
    }
}

/// Coordinator knowledge of the external advertiser's state.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VipOwnershipState {
    /// No provider mutation has completed since this coordinator was built.
    ///
    /// A stale advertisement may predate this process, so the first reconcile
    /// must withdraw before it can claim known state.
    #[default]
    Uninitialized,
    /// The exact VIP advertisement is known to be withdrawn.
    Withdrawn,
    /// The exact VIP advertisement is confirmed under this fence.
    Advertised {
        /// Leadership fence authorizing the advertisement.
        fence: LeadershipFence,
    },
    /// A provider mutation was cancelled or returned an error, so the exact
    /// external state is unknown.
    ///
    /// The next reconcile first withdraws the exact advertisement to converge
    /// on known-absent state. `retry_fence` is present only while the complete
    /// owner signal that authorized an advertisement remains valid; any loss
    /// of leadership, quorum, health, or fence validity revokes it.
    ProviderStateUnknown {
        /// Fence associated with the last possibly active advertisement.
        ///
        /// This is `None` while the coordinator is cleaning up state that may
        /// predate this process.
        last_fence: Option<LeadershipFence>,
        /// Exact epoch still authorized for retry after cleanup.
        retry_fence: Option<LeadershipFence>,
    },
}

/// Reconciles one VIP against caller-supplied leadership, quorum, health, and
/// fence evidence.
///
/// The coordinator advertises only on a complete owner signal carrying a
/// previously unseen fence. Repeating the same complete intent while that
/// exact fence remains advertised is an idempotent no-op. Once the VIP is
/// withdrawn, re-advertisement requires a strictly newer fence; this prevents
/// a stale caller or an ABA return without an epoch bump from regaining the
/// VIP.
///
/// The coordinator contains no key material and has no dependency on SA or
/// shard ownership. Callers should serialize calls to [`Self::reconcile`]; its
/// mutable receiver enforces that for one coordinator instance.
#[derive(Debug)]
pub struct VipOwnershipCoordinator<A> {
    advertiser: A,
    advertisement: VipAdvertisement,
    highest_observed_fence: Option<LeadershipFence>,
    state: VipOwnershipState,
}

impl<A> VipOwnershipCoordinator<A>
where
    A: VipAdvertiser,
{
    /// Build an uninitialized coordinator for one VIP and advertiser.
    ///
    /// The first reconcile always withdraws the exact advertisement because a
    /// stale provider route may predate this process.
    #[must_use]
    pub const fn new(advertisement: VipAdvertisement, advertiser: A) -> Self {
        Self {
            advertiser,
            advertisement,
            highest_observed_fence: None,
            state: VipOwnershipState::Uninitialized,
        }
    }

    /// Reconcile the provider with the latest caller-supplied ownership intent.
    ///
    /// Advertisement requires all three booleans, a fence, and a fence newer
    /// than every fence previously observed by this coordinator. An identical
    /// intent is retained only while its exact fence is already advertised.
    /// Missing, regressing, or equal-after-withdraw fences fail closed.
    ///
    /// Before awaiting a provider mutation, the coordinator records
    /// [`VipOwnershipState::ProviderStateUnknown`]. After an error or
    /// cancellation, the next reconcile withdraws the exact advertisement to
    /// establish known-absent state before any authorized retry. Fence history
    /// is never erased, and losing any owner signal revokes an in-flight
    /// epoch's retry authorization.
    pub async fn reconcile(&mut self, intent: VipOwnershipIntent) -> Result<(), IpsecLbError> {
        let previous_highest = self.highest_observed_fence;
        if let Some(fence) = intent.fence {
            if self
                .highest_observed_fence
                .is_none_or(|highest| fence > highest)
            {
                self.highest_observed_fence = Some(fence);
            }
        }

        let complete = intent.has_complete_owner_signal();
        let fresh_fence = intent
            .fence
            .filter(|fence| complete && previous_highest.is_none_or(|highest| *fence > highest));

        match self.state {
            VipOwnershipState::Uninitialized => {
                self.state = VipOwnershipState::ProviderStateUnknown {
                    last_fence: None,
                    retry_fence: fresh_fence,
                };
                self.converge_withdrawn().await?;
                if let Some(fence) = fresh_fence {
                    self.attempt_advertise(fence).await?;
                }
                Ok(())
            }
            VipOwnershipState::Withdrawn => {
                if let Some(fence) = fresh_fence {
                    self.attempt_advertise(fence).await?;
                }
                Ok(())
            }
            VipOwnershipState::Advertised { fence } => {
                let retains_current_epoch = complete
                    && intent.fence == Some(fence)
                    && self.highest_observed_fence == Some(fence);
                if retains_current_epoch {
                    return Ok(());
                }

                if let Some(fresh_fence) = fresh_fence {
                    // The exact VIP and node have not changed, and the route
                    // is already confirmed. Advancing only the local accepted
                    // leadership epoch needs no duplicate provider mutation.
                    self.state = VipOwnershipState::Advertised { fence: fresh_fence };
                    return Ok(());
                }

                self.state = VipOwnershipState::ProviderStateUnknown {
                    last_fence: Some(fence),
                    retry_fence: None,
                };
                self.converge_withdrawn().await
            }
            VipOwnershipState::ProviderStateUnknown {
                last_fence,
                retry_fence,
            } => {
                let retained_retry = retry_fence.filter(|retry_fence| {
                    complete
                        && intent.fence == Some(*retry_fence)
                        && self.highest_observed_fence == Some(*retry_fence)
                });
                let retry_target = fresh_fence.or(retained_retry);

                // Record revocation or a newly authorized target before the
                // cleanup await so cancellation cannot retain stale authority.
                self.state = VipOwnershipState::ProviderStateUnknown {
                    last_fence,
                    retry_fence: retry_target,
                };
                self.converge_withdrawn().await?;
                if let Some(fence) = retry_target {
                    self.attempt_advertise(fence).await?;
                }
                Ok(())
            }
        }
    }

    async fn attempt_advertise(&mut self, fence: LeadershipFence) -> Result<(), IpsecLbError> {
        self.state = VipOwnershipState::ProviderStateUnknown {
            last_fence: Some(fence),
            retry_fence: Some(fence),
        };
        self.advertiser
            .advertise(self.advertisement.clone())
            .await?;
        self.state = VipOwnershipState::Advertised { fence };
        Ok(())
    }

    async fn converge_withdrawn(&mut self) -> Result<(), IpsecLbError> {
        match self.advertiser.withdraw(self.advertisement.clone()).await {
            Ok(()) | Err(IpsecLbError::NotFound) => {
                self.state = VipOwnershipState::Withdrawn;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Return whether the provider has confirmed the VIP as advertised.
    ///
    /// This returns `false` for uninitialized, withdrawn, and provider-unknown
    /// state. Use [`Self::state`] when that distinction matters.
    #[must_use]
    pub const fn is_advertised(&self) -> bool {
        matches!(self.state, VipOwnershipState::Advertised { .. })
    }

    /// Return the fence under which the provider confirmed the VIP advertised.
    #[must_use]
    pub const fn advertised_fence(&self) -> Option<LeadershipFence> {
        match self.state {
            VipOwnershipState::Advertised { fence } => Some(fence),
            VipOwnershipState::Uninitialized
            | VipOwnershipState::Withdrawn
            | VipOwnershipState::ProviderStateUnknown { .. } => None,
        }
    }

    /// Return the coordinator's exact provider-state knowledge.
    #[must_use]
    pub const fn state(&self) -> VipOwnershipState {
        self.state
    }

    /// Return the greatest leadership fence observed by this coordinator.
    #[must_use]
    pub const fn highest_observed_fence(&self) -> Option<LeadershipFence> {
        self.highest_observed_fence
    }

    /// Return the VIP advertisement owned by this coordinator.
    #[must_use]
    pub const fn advertisement(&self) -> &VipAdvertisement {
        &self.advertisement
    }
}

#[cfg(test)]
mod tests {
    use std::future::{pending, Future};
    use std::io;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    use async_trait::async_trait;

    use super::*;
    use crate::model::{ClusterNode, IpAddress, VipProbe};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ScriptedFailure {
        None,
        AdvertiseBeforeApply,
        AdvertiseAfterApply,
        AdvertiseAlreadyExists,
        WithdrawAfterApply,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ScriptedOperation {
        Advertise,
        Withdraw,
    }

    #[derive(Debug, Clone)]
    struct ScriptedAdvertiser {
        state: Arc<Mutex<ScriptedState>>,
    }

    #[derive(Debug)]
    struct ScriptedState {
        active: bool,
        failure: ScriptedFailure,
        hang_advertise_after_apply: bool,
        hang_withdraw_after_apply: bool,
        operations: Vec<ScriptedOperation>,
    }

    impl ScriptedAdvertiser {
        fn new(failure: ScriptedFailure) -> Self {
            Self {
                state: Arc::new(Mutex::new(ScriptedState {
                    active: false,
                    failure,
                    hang_advertise_after_apply: false,
                    hang_withdraw_after_apply: false,
                    operations: Vec::new(),
                })),
            }
        }

        fn set_failure(&self, failure: ScriptedFailure) {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.failure = failure;
        }

        fn snapshot(&self) -> (bool, Vec<ScriptedOperation>) {
            let state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (state.active, state.operations.clone())
        }

        fn preseed_active(&self) {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.active = true;
        }

        fn clear_operations(&self) {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.operations.clear();
        }

        fn hang_next_advertise_after_apply(&self) {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.hang_advertise_after_apply = true;
        }

        fn hang_next_withdraw_after_apply(&self) {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.hang_withdraw_after_apply = true;
        }

        fn ambiguous_error(operation: &'static str) -> IpsecLbError {
            IpsecLbError::io(
                operation,
                io::Error::new(io::ErrorKind::TimedOut, "scripted ambiguous result"),
            )
        }
    }

    #[async_trait]
    impl VipAdvertiser for ScriptedAdvertiser {
        async fn advertise(&self, _advertisement: VipAdvertisement) -> Result<(), IpsecLbError> {
            let (hang, result) = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state.operations.push(ScriptedOperation::Advertise);
                let failure = match state.failure {
                    ScriptedFailure::AdvertiseBeforeApply
                    | ScriptedFailure::AdvertiseAfterApply
                    | ScriptedFailure::AdvertiseAlreadyExists => {
                        std::mem::replace(&mut state.failure, ScriptedFailure::None)
                    }
                    ScriptedFailure::None | ScriptedFailure::WithdrawAfterApply => {
                        ScriptedFailure::None
                    }
                };
                let hang = std::mem::take(&mut state.hang_advertise_after_apply);
                let result = match failure {
                    ScriptedFailure::AdvertiseBeforeApply => {
                        Err(Self::ambiguous_error("scripted_advertise"))
                    }
                    ScriptedFailure::AdvertiseAfterApply => {
                        state.active = true;
                        Err(Self::ambiguous_error("scripted_advertise"))
                    }
                    ScriptedFailure::AdvertiseAlreadyExists => {
                        state.active = true;
                        Err(IpsecLbError::AlreadyExists)
                    }
                    ScriptedFailure::None | ScriptedFailure::WithdrawAfterApply => {
                        if state.active {
                            Err(IpsecLbError::AlreadyExists)
                        } else {
                            state.active = true;
                            Ok(())
                        }
                    }
                };
                if hang {
                    state.active = true;
                }
                (hang, result)
            };
            if hang {
                pending::<()>().await;
            }
            result
        }

        async fn withdraw(&self, _advertisement: VipAdvertisement) -> Result<(), IpsecLbError> {
            let (hang, result) = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state.operations.push(ScriptedOperation::Withdraw);
                let failure = if state.failure == ScriptedFailure::WithdrawAfterApply {
                    std::mem::replace(&mut state.failure, ScriptedFailure::None)
                } else {
                    ScriptedFailure::None
                };
                let hang = std::mem::take(&mut state.hang_withdraw_after_apply);
                let result = if failure == ScriptedFailure::WithdrawAfterApply {
                    state.active = false;
                    Err(Self::ambiguous_error("scripted_withdraw"))
                } else if state.active {
                    state.active = false;
                    Ok(())
                } else {
                    Err(IpsecLbError::NotFound)
                };
                if hang {
                    state.active = false;
                }
                (hang, result)
            };
            if hang {
                pending::<()>().await;
            }
            result
        }

        async fn probe(&self) -> Result<VipProbe, IpsecLbError> {
            Ok(VipProbe::mock())
        }
    }

    fn advertisement() -> VipAdvertisement {
        VipAdvertisement {
            vip: IpAddress::V4([192, 0, 2, 40]),
            node: ClusterNode::new("control-a"),
        }
    }

    fn owner_intent(value: u64) -> VipOwnershipIntent {
        VipOwnershipIntent {
            leader: true,
            quorum_available: true,
            healthy: true,
            fence: Some(LeadershipFence::new(value).unwrap()),
        }
    }

    fn assert_pending<F>(future: &mut std::pin::Pin<Box<F>>)
    where
        F: Future,
    {
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    }

    async fn initialize(coordinator: &mut VipOwnershipCoordinator<ScriptedAdvertiser>) {
        coordinator
            .reconcile(VipOwnershipIntent::default())
            .await
            .unwrap();
        assert_eq!(coordinator.state(), VipOwnershipState::Withdrawn);
    }

    #[test]
    fn leadership_fence_rejects_zero() {
        assert!(matches!(
            LeadershipFence::new(0),
            Err(IpsecLbError::InvalidConfig {
                field: "leadership_fence",
                ..
            })
        ));
        assert_eq!(LeadershipFence::new(7).unwrap().get(), 7);
    }

    #[test]
    fn default_intent_is_fail_closed() {
        let intent = VipOwnershipIntent::default();
        assert!(!intent.leader);
        assert!(!intent.quorum_available);
        assert!(!intent.healthy);
        assert_eq!(intent.fence, None);
        assert!(!intent.has_complete_owner_signal());
    }

    #[tokio::test]
    async fn fresh_coordinator_withdraws_preexisting_route_for_default_intent() {
        let advertiser = ScriptedAdvertiser::new(ScriptedFailure::None);
        advertiser.preseed_active();
        let mut coordinator = VipOwnershipCoordinator::new(advertisement(), advertiser.clone());
        assert_eq!(coordinator.state(), VipOwnershipState::Uninitialized);

        coordinator
            .reconcile(VipOwnershipIntent::default())
            .await
            .unwrap();

        assert_eq!(coordinator.state(), VipOwnershipState::Withdrawn);
        assert_eq!(
            advertiser.snapshot(),
            (false, vec![ScriptedOperation::Withdraw])
        );
    }

    #[tokio::test]
    async fn valid_first_intent_cleans_unknown_state_before_advertising() {
        let advertiser = ScriptedAdvertiser::new(ScriptedFailure::None);
        let mut coordinator = VipOwnershipCoordinator::new(advertisement(), advertiser.clone());
        let fence = LeadershipFence::new(5).unwrap();

        coordinator.reconcile(owner_intent(5)).await.unwrap();

        assert_eq!(coordinator.state(), VipOwnershipState::Advertised { fence });
        assert_eq!(
            advertiser.snapshot(),
            (
                true,
                vec![ScriptedOperation::Withdraw, ScriptedOperation::Advertise],
            )
        );
    }

    #[tokio::test]
    async fn advertise_error_after_apply_retries_same_epoch_via_cleanup() {
        let advertiser = ScriptedAdvertiser::new(ScriptedFailure::None);
        let mut coordinator = VipOwnershipCoordinator::new(advertisement(), advertiser.clone());
        initialize(&mut coordinator).await;
        advertiser.clear_operations();
        advertiser.set_failure(ScriptedFailure::AdvertiseAfterApply);
        let fence = LeadershipFence::new(10).unwrap();

        assert!(coordinator.reconcile(owner_intent(10)).await.is_err());
        assert_eq!(
            coordinator.state(),
            VipOwnershipState::ProviderStateUnknown {
                last_fence: Some(fence),
                retry_fence: Some(fence),
            }
        );
        assert_eq!(
            advertiser.snapshot(),
            (true, vec![ScriptedOperation::Advertise])
        );

        coordinator.reconcile(owner_intent(10)).await.unwrap();
        assert_eq!(coordinator.state(), VipOwnershipState::Advertised { fence });
        assert_eq!(
            advertiser.snapshot(),
            (
                true,
                vec![
                    ScriptedOperation::Advertise,
                    ScriptedOperation::Withdraw,
                    ScriptedOperation::Advertise,
                ],
            )
        );

        coordinator.reconcile(owner_intent(10)).await.unwrap();
        assert_eq!(advertiser.snapshot().1.len(), 3);
    }

    #[tokio::test]
    async fn advertise_error_before_apply_retries_after_not_found_cleanup() {
        let advertiser = ScriptedAdvertiser::new(ScriptedFailure::None);
        let mut coordinator = VipOwnershipCoordinator::new(advertisement(), advertiser.clone());
        initialize(&mut coordinator).await;
        advertiser.clear_operations();
        advertiser.set_failure(ScriptedFailure::AdvertiseBeforeApply);
        let fence = LeadershipFence::new(20).unwrap();

        assert!(coordinator.reconcile(owner_intent(20)).await.is_err());
        assert!(!advertiser.snapshot().0);

        coordinator.reconcile(owner_intent(20)).await.unwrap();
        assert_eq!(coordinator.state(), VipOwnershipState::Advertised { fence });
        assert_eq!(
            advertiser.snapshot(),
            (
                true,
                vec![
                    ScriptedOperation::Advertise,
                    ScriptedOperation::Withdraw,
                    ScriptedOperation::Advertise,
                ],
            )
        );
    }

    #[tokio::test]
    async fn advertise_error_then_owner_loss_withdraws_maybe_applied_route() {
        let advertiser = ScriptedAdvertiser::new(ScriptedFailure::None);
        let mut coordinator = VipOwnershipCoordinator::new(advertisement(), advertiser.clone());
        initialize(&mut coordinator).await;
        advertiser.clear_operations();
        advertiser.set_failure(ScriptedFailure::AdvertiseAfterApply);
        let fence = LeadershipFence::new(30).unwrap();

        assert!(coordinator.reconcile(owner_intent(30)).await.is_err());
        coordinator
            .reconcile(VipOwnershipIntent {
                leader: false,
                ..owner_intent(30)
            })
            .await
            .unwrap();

        assert_eq!(coordinator.state(), VipOwnershipState::Withdrawn);
        assert_eq!(coordinator.highest_observed_fence(), Some(fence));
        assert_eq!(
            advertiser.snapshot(),
            (
                false,
                vec![ScriptedOperation::Advertise, ScriptedOperation::Withdraw,],
            )
        );
        coordinator.reconcile(owner_intent(30)).await.unwrap();
        assert_eq!(coordinator.state(), VipOwnershipState::Withdrawn);
        assert_eq!(advertiser.snapshot().1.len(), 2);
    }

    #[tokio::test]
    async fn withdraw_error_after_apply_converges_and_revokes_old_epoch() {
        let advertiser = ScriptedAdvertiser::new(ScriptedFailure::None);
        let mut coordinator = VipOwnershipCoordinator::new(advertisement(), advertiser.clone());
        initialize(&mut coordinator).await;
        advertiser.clear_operations();
        let fence = LeadershipFence::new(40).unwrap();
        coordinator.reconcile(owner_intent(40)).await.unwrap();
        advertiser.set_failure(ScriptedFailure::WithdrawAfterApply);

        let lost = VipOwnershipIntent {
            healthy: false,
            ..owner_intent(40)
        };
        assert!(coordinator.reconcile(lost).await.is_err());
        assert_eq!(
            coordinator.state(),
            VipOwnershipState::ProviderStateUnknown {
                last_fence: Some(fence),
                retry_fence: None,
            }
        );
        assert!(!advertiser.snapshot().0);

        // A recovered healthy signal cannot resurrect the revoked epoch; this
        // call only converges the ambiguous withdrawal to known absence.
        coordinator.reconcile(owner_intent(40)).await.unwrap();
        assert_eq!(coordinator.state(), VipOwnershipState::Withdrawn);
        coordinator.reconcile(owner_intent(40)).await.unwrap();
        assert_eq!(coordinator.state(), VipOwnershipState::Withdrawn);
        coordinator.reconcile(owner_intent(41)).await.unwrap();
        assert_eq!(
            coordinator.state(),
            VipOwnershipState::Advertised {
                fence: LeadershipFence::new(41).unwrap(),
            }
        );
        assert_eq!(
            advertiser.snapshot().1,
            vec![
                ScriptedOperation::Advertise,
                ScriptedOperation::Withdraw,
                ScriptedOperation::Withdraw,
                ScriptedOperation::Advertise,
            ]
        );
    }

    #[tokio::test]
    async fn already_exists_remains_unknown_until_cleanup_and_success() {
        let advertiser = ScriptedAdvertiser::new(ScriptedFailure::AdvertiseAlreadyExists);
        let mut coordinator = VipOwnershipCoordinator::new(advertisement(), advertiser.clone());
        let fence = LeadershipFence::new(50).unwrap();

        assert!(matches!(
            coordinator.reconcile(owner_intent(50)).await,
            Err(IpsecLbError::AlreadyExists)
        ));
        assert_eq!(
            coordinator.state(),
            VipOwnershipState::ProviderStateUnknown {
                last_fence: Some(fence),
                retry_fence: Some(fence),
            }
        );
        assert_eq!(
            advertiser.snapshot(),
            (
                true,
                vec![ScriptedOperation::Withdraw, ScriptedOperation::Advertise],
            )
        );

        coordinator.reconcile(owner_intent(50)).await.unwrap();
        assert_eq!(coordinator.state(), VipOwnershipState::Advertised { fence });
        assert_eq!(
            advertiser.snapshot(),
            (
                true,
                vec![
                    ScriptedOperation::Withdraw,
                    ScriptedOperation::Advertise,
                    ScriptedOperation::Withdraw,
                    ScriptedOperation::Advertise,
                ],
            )
        );
    }

    #[tokio::test]
    async fn confirmed_route_advances_to_fresh_epoch_without_duplicate_mutation() {
        let advertiser = ScriptedAdvertiser::new(ScriptedFailure::None);
        let mut coordinator = VipOwnershipCoordinator::new(advertisement(), advertiser.clone());
        initialize(&mut coordinator).await;
        advertiser.clear_operations();
        coordinator.reconcile(owner_intent(60)).await.unwrap();
        advertiser.clear_operations();

        coordinator.reconcile(owner_intent(61)).await.unwrap();
        coordinator.reconcile(owner_intent(61)).await.unwrap();

        assert_eq!(
            coordinator.state(),
            VipOwnershipState::Advertised {
                fence: LeadershipFence::new(61).unwrap(),
            }
        );
        assert_eq!(
            coordinator.highest_observed_fence(),
            Some(LeadershipFence::new(61).unwrap())
        );
        assert_eq!(advertiser.snapshot(), (true, Vec::new()));
    }

    #[tokio::test]
    async fn cancelled_advertise_is_unknown_and_owner_loss_cleans_it_up() {
        let advertiser = ScriptedAdvertiser::new(ScriptedFailure::None);
        let mut coordinator = VipOwnershipCoordinator::new(advertisement(), advertiser.clone());
        initialize(&mut coordinator).await;
        advertiser.clear_operations();
        advertiser.hang_next_advertise_after_apply();
        let fence = LeadershipFence::new(70).unwrap();

        let mut reconcile = Box::pin(coordinator.reconcile(owner_intent(70)));
        assert_pending(&mut reconcile);
        drop(reconcile);

        assert_eq!(
            coordinator.state(),
            VipOwnershipState::ProviderStateUnknown {
                last_fence: Some(fence),
                retry_fence: Some(fence),
            }
        );
        assert_eq!(
            advertiser.snapshot(),
            (true, vec![ScriptedOperation::Advertise])
        );

        coordinator
            .reconcile(VipOwnershipIntent {
                leader: false,
                ..owner_intent(70)
            })
            .await
            .unwrap();
        assert_eq!(coordinator.state(), VipOwnershipState::Withdrawn);
        assert_eq!(
            advertiser.snapshot(),
            (
                false,
                vec![ScriptedOperation::Advertise, ScriptedOperation::Withdraw],
            )
        );
        coordinator.reconcile(owner_intent(70)).await.unwrap();
        assert_eq!(coordinator.state(), VipOwnershipState::Withdrawn);
    }

    #[tokio::test]
    async fn cancelled_withdraw_is_unknown_and_revokes_the_old_epoch() {
        let advertiser = ScriptedAdvertiser::new(ScriptedFailure::None);
        let mut coordinator = VipOwnershipCoordinator::new(advertisement(), advertiser.clone());
        initialize(&mut coordinator).await;
        coordinator.reconcile(owner_intent(80)).await.unwrap();
        advertiser.clear_operations();
        advertiser.hang_next_withdraw_after_apply();
        let fence = LeadershipFence::new(80).unwrap();
        let lost = VipOwnershipIntent {
            quorum_available: false,
            ..owner_intent(80)
        };

        let mut reconcile = Box::pin(coordinator.reconcile(lost));
        assert_pending(&mut reconcile);
        drop(reconcile);

        assert_eq!(
            coordinator.state(),
            VipOwnershipState::ProviderStateUnknown {
                last_fence: Some(fence),
                retry_fence: None,
            }
        );
        assert_eq!(
            advertiser.snapshot(),
            (false, vec![ScriptedOperation::Withdraw])
        );

        // Even a recovered full signal cannot revive the revoked epoch. It
        // only completes cleanup of the ambiguous withdrawal.
        coordinator.reconcile(owner_intent(80)).await.unwrap();
        assert_eq!(coordinator.state(), VipOwnershipState::Withdrawn);
        coordinator.reconcile(owner_intent(80)).await.unwrap();
        assert_eq!(coordinator.state(), VipOwnershipState::Withdrawn);
        assert_eq!(
            advertiser.snapshot(),
            (
                false,
                vec![ScriptedOperation::Withdraw, ScriptedOperation::Withdraw],
            )
        );

        coordinator.reconcile(owner_intent(81)).await.unwrap();
        assert_eq!(
            coordinator.state(),
            VipOwnershipState::Advertised {
                fence: LeadershipFence::new(81).unwrap(),
            }
        );
    }
}
