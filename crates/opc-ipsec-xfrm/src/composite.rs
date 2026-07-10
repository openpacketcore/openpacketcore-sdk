//! Composite XFRM operations with deterministic rollback evidence.

use std::{error::Error, fmt};

use crate::{
    InstallPolicyRequest, InstallSaRequest, RekeyPolicyRequest, RekeySaRequest,
    RemovePolicyRequest, RemoveSaRequest, XfrmBackend, XfrmError,
};

/// Stable operation label for composite XFRM workflows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmCompositeOperation {
    /// Install a Security Association.
    InstallSa,
    /// Install a Security Policy.
    InstallPolicy,
    /// Remove a Security Association during rollback.
    RollbackRemoveSa,
    /// Rekey a Security Association.
    RekeySa,
    /// Rekey a Security Policy.
    RekeyPolicy,
    /// Remove a Security Policy.
    RemovePolicy,
    /// Remove a Security Association.
    RemoveSa,
}

impl XfrmCompositeOperation {
    /// Stable machine-readable operation name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InstallSa => "install_sa",
            Self::InstallPolicy => "install_policy",
            Self::RollbackRemoveSa => "rollback_remove_sa",
            Self::RekeySa => "rekey_sa",
            Self::RekeyPolicy => "rekey_policy",
            Self::RemovePolicy => "remove_policy",
            Self::RemoveSa => "remove_sa",
        }
    }
}

/// Stable install operation ordering: SA first, policy second.
pub const XFRM_COMPOSITE_INSTALL_ORDER: [XfrmCompositeOperation; 2] = [
    XfrmCompositeOperation::InstallSa,
    XfrmCompositeOperation::InstallPolicy,
];

/// Stable install rollback ordering after policy failure.
pub const XFRM_COMPOSITE_INSTALL_ROLLBACK_ORDER: [XfrmCompositeOperation; 1] =
    [XfrmCompositeOperation::RollbackRemoveSa];

/// Stable rekey operation ordering: SA first, policy second.
pub const XFRM_COMPOSITE_REKEY_ORDER: [XfrmCompositeOperation; 2] = [
    XfrmCompositeOperation::RekeySa,
    XfrmCompositeOperation::RekeyPolicy,
];

/// Stable remove operation ordering: policy first, SA second.
pub const XFRM_COMPOSITE_REMOVE_ORDER: [XfrmCompositeOperation; 2] = [
    XfrmCompositeOperation::RemovePolicy,
    XfrmCompositeOperation::RemoveSa,
];

/// Request to install an SA plus its policy as a composite operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XfrmCompositeInstallRequest {
    /// Security Association install request.
    pub sa: InstallSaRequest,
    /// Security Policy install request.
    pub policy: InstallPolicyRequest,
}

impl XfrmCompositeInstallRequest {
    /// Build the rollback request for the SA installed by this composite.
    pub fn rollback_remove_sa(&self) -> RemoveSaRequest {
        RemoveSaRequest {
            destination: self.sa.parameters.id.destination,
            protocol: self.sa.parameters.id.protocol,
            spi: self.sa.parameters.id.spi,
        }
    }

    /// Build the rollback request for the policy installed by this composite.
    pub fn rollback_remove_policy(&self) -> RemovePolicyRequest {
        RemovePolicyRequest {
            selector: self.policy.parameters.selector.clone(),
            direction: self.policy.parameters.direction,
        }
    }
}

/// Redaction-safe composite operation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XfrmCompositeOutcome {
    /// True when the full composite operation applied.
    pub applied: bool,
    /// True when the operation rolled back all mutation it had applied.
    pub rolled_back: bool,
    /// True when rollback was attempted and failed.
    pub rollback_failed: bool,
    /// True when installed residue may remain in the backend.
    pub partial_state_possible: bool,
    /// Operation that failed, if any.
    pub failed_operation: Option<XfrmCompositeOperation>,
}

impl XfrmCompositeOutcome {
    /// Fully applied composite outcome.
    pub const fn applied() -> Self {
        Self {
            applied: true,
            rolled_back: false,
            rollback_failed: false,
            partial_state_possible: false,
            failed_operation: None,
        }
    }

    /// Failed before any composite mutation remained applied.
    pub const fn not_applied(failed_operation: XfrmCompositeOperation) -> Self {
        Self {
            applied: false,
            rolled_back: false,
            rollback_failed: false,
            partial_state_possible: false,
            failed_operation: Some(failed_operation),
        }
    }

    /// Failed after SA install and successfully rolled it back.
    pub const fn rolled_back(failed_operation: XfrmCompositeOperation) -> Self {
        Self {
            applied: false,
            rolled_back: true,
            rollback_failed: false,
            partial_state_possible: false,
            failed_operation: Some(failed_operation),
        }
    }

    /// Failed after SA install and rollback also failed.
    pub const fn rollback_failed(failed_operation: XfrmCompositeOperation) -> Self {
        Self {
            applied: false,
            rolled_back: false,
            rollback_failed: true,
            partial_state_possible: true,
            failed_operation: Some(failed_operation),
        }
    }
}

/// Error returned by an SA-plus-policy install composite.
#[derive(Debug, Clone)]
pub enum XfrmCompositeInstallError {
    /// SA install failed before policy install was attempted.
    InstallSaFailed {
        /// Backend error from SA install.
        source: XfrmError,
        /// Composite outcome evidence.
        outcome: XfrmCompositeOutcome,
    },
    /// Policy install failed after SA install and rollback succeeded.
    PolicyInstallRolledBack {
        /// Backend error from policy install.
        source: XfrmError,
        /// Composite outcome evidence.
        outcome: XfrmCompositeOutcome,
    },
    /// Policy install failed after SA install and rollback also failed.
    PolicyInstallRollbackFailed {
        /// Backend error from policy install.
        source: XfrmError,
        /// Backend error from rollback SA removal.
        rollback: XfrmError,
        /// Composite outcome evidence.
        outcome: XfrmCompositeOutcome,
    },
}

impl XfrmCompositeInstallError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InstallSaFailed { .. } => "xfrm_composite_install_sa_failed",
            Self::PolicyInstallRolledBack { .. } => "xfrm_composite_policy_install_rolled_back",
            Self::PolicyInstallRollbackFailed { .. } => {
                "xfrm_composite_policy_install_rollback_failed"
            }
        }
    }

    /// Return the composite outcome evidence.
    pub const fn outcome(&self) -> XfrmCompositeOutcome {
        match self {
            Self::InstallSaFailed { outcome, .. }
            | Self::PolicyInstallRolledBack { outcome, .. }
            | Self::PolicyInstallRollbackFailed { outcome, .. } => *outcome,
        }
    }
}

impl fmt::Display for XfrmCompositeInstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for XfrmCompositeInstallError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InstallSaFailed { source, .. }
            | Self::PolicyInstallRolledBack { source, .. }
            | Self::PolicyInstallRollbackFailed { source, .. } => Some(source),
        }
    }
}

/// Redaction-safe outcome for a two-direction SA/policy install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XfrmBidirectionalInstallOutcome {
    /// True when both directions fully applied.
    pub applied: bool,
    /// Outcome for the first direction.
    pub first: XfrmCompositeOutcome,
    /// Outcome for the second direction.
    pub second: XfrmCompositeOutcome,
    /// True when the first direction was removed after second-direction failure.
    pub cross_rolled_back: bool,
    /// True when removing the first direction failed.
    pub cross_rollback_failed: bool,
    /// True when installed residue may remain in either direction.
    pub partial_state_possible: bool,
}

impl XfrmBidirectionalInstallOutcome {
    /// Both directions applied.
    pub const fn applied(first: XfrmCompositeOutcome, second: XfrmCompositeOutcome) -> Self {
        Self {
            applied: true,
            first,
            second,
            cross_rolled_back: false,
            cross_rollback_failed: false,
            partial_state_possible: false,
        }
    }

    fn first_failed(first: XfrmCompositeOutcome) -> Self {
        Self {
            applied: false,
            first,
            second: XfrmCompositeOutcome::not_applied(XfrmCompositeOperation::InstallSa),
            cross_rolled_back: false,
            cross_rollback_failed: false,
            partial_state_possible: first.partial_state_possible,
        }
    }

    fn second_failed(
        second: XfrmCompositeOutcome,
        cross_rolled_back: bool,
        cross_rollback_failed: bool,
    ) -> Self {
        Self {
            applied: false,
            first: XfrmCompositeOutcome::applied(),
            second,
            cross_rolled_back,
            cross_rollback_failed,
            partial_state_possible: second.partial_state_possible || cross_rollback_failed,
        }
    }
}

/// Error returned by a two-direction SA/policy install.
#[derive(Debug, Clone)]
pub enum XfrmBidirectionalInstallError {
    /// First direction failed before the second direction was attempted.
    FirstInstallFailed {
        /// Backend/composite error from the first direction.
        source: XfrmCompositeInstallError,
        /// Bidirectional outcome evidence.
        outcome: XfrmBidirectionalInstallOutcome,
    },
    /// Second direction failed and the first direction was rolled back.
    SecondInstallRolledBack {
        /// Backend/composite error from the second direction.
        source: XfrmCompositeInstallError,
        /// Bidirectional outcome evidence.
        outcome: XfrmBidirectionalInstallOutcome,
    },
    /// Second direction failed and rollback of the first direction also failed.
    SecondInstallRollbackFailed {
        /// Backend/composite error from the second direction.
        source: XfrmCompositeInstallError,
        /// Backend error from first-direction rollback.
        rollback: XfrmError,
        /// Bidirectional outcome evidence.
        outcome: XfrmBidirectionalInstallOutcome,
    },
}

impl XfrmBidirectionalInstallError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::FirstInstallFailed { .. } => "xfrm_bidirectional_first_install_failed",
            Self::SecondInstallRolledBack { .. } => "xfrm_bidirectional_second_install_rolled_back",
            Self::SecondInstallRollbackFailed { .. } => {
                "xfrm_bidirectional_second_install_rollback_failed"
            }
        }
    }

    /// Return the bidirectional outcome evidence.
    pub const fn outcome(&self) -> XfrmBidirectionalInstallOutcome {
        match self {
            Self::FirstInstallFailed { outcome, .. }
            | Self::SecondInstallRolledBack { outcome, .. }
            | Self::SecondInstallRollbackFailed { outcome, .. } => *outcome,
        }
    }
}

impl fmt::Display for XfrmBidirectionalInstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for XfrmBidirectionalInstallError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::FirstInstallFailed { source, .. }
            | Self::SecondInstallRolledBack { source, .. }
            | Self::SecondInstallRollbackFailed { source, .. } => Some(source),
        }
    }
}

/// Install a Security Association and its Security Policy with best-effort rollback.
///
/// Operation order is [`XFRM_COMPOSITE_INSTALL_ORDER`]. If policy install
/// fails after SA install succeeds, the helper attempts
/// [`XFRM_COMPOSITE_INSTALL_ROLLBACK_ORDER`] by removing the installed SA.
///
/// # Errors
///
/// Returns [`XfrmCompositeInstallError`] preserving the original backend error
/// and, when rollback fails, the rollback backend error.
pub async fn install_sa_policy_with_rollback<B>(
    backend: &B,
    request: XfrmCompositeInstallRequest,
) -> Result<XfrmCompositeOutcome, XfrmCompositeInstallError>
where
    B: XfrmBackend + ?Sized,
{
    if let Err(source) = backend.install_sa(request.sa.clone()).await {
        return Err(XfrmCompositeInstallError::InstallSaFailed {
            source,
            outcome: XfrmCompositeOutcome::not_applied(XfrmCompositeOperation::InstallSa),
        });
    }

    if let Err(source) = backend.install_policy(request.policy.clone()).await {
        let rollback_request = request.rollback_remove_sa();
        return match backend.remove_sa(rollback_request).await {
            Ok(()) => Err(XfrmCompositeInstallError::PolicyInstallRolledBack {
                source,
                outcome: XfrmCompositeOutcome::rolled_back(XfrmCompositeOperation::InstallPolicy),
            }),
            Err(rollback) => Err(XfrmCompositeInstallError::PolicyInstallRollbackFailed {
                source,
                rollback,
                outcome: XfrmCompositeOutcome::rollback_failed(
                    XfrmCompositeOperation::InstallPolicy,
                ),
            }),
        };
    }

    Ok(XfrmCompositeOutcome::applied())
}

/// Install both directions of a Child SA and roll back cross-direction residue.
///
/// The first request is installed before the second. If the second direction
/// fails, this helper removes the first direction's policy and SA in
/// [`XFRM_COMPOSITE_REMOVE_ORDER`] so a half-installed bidirectional tunnel is
/// not left behind.
///
/// # Errors
///
/// Returns [`XfrmBidirectionalInstallError`] with outcome evidence preserving
/// both the failed composite result and any rollback failure.
pub async fn install_bidirectional_sa_policy_with_rollback<B>(
    backend: &B,
    requests: [XfrmCompositeInstallRequest; 2],
) -> Result<XfrmBidirectionalInstallOutcome, XfrmBidirectionalInstallError>
where
    B: XfrmBackend + ?Sized,
{
    let [first, second] = requests;

    let first_outcome = match install_sa_policy_with_rollback(backend, first.clone()).await {
        Ok(outcome) => outcome,
        Err(source) => {
            return Err(XfrmBidirectionalInstallError::FirstInstallFailed {
                outcome: XfrmBidirectionalInstallOutcome::first_failed(source.outcome()),
                source,
            })
        }
    };

    let second_outcome = match install_sa_policy_with_rollback(backend, second).await {
        Ok(outcome) => outcome,
        Err(source) => {
            let second_outcome = source.outcome();
            let rollback = remove_policy_sa(
                backend,
                first.rollback_remove_policy(),
                first.rollback_remove_sa(),
            )
            .await;
            return match rollback {
                Ok(_) => Err(XfrmBidirectionalInstallError::SecondInstallRolledBack {
                    outcome: XfrmBidirectionalInstallOutcome::second_failed(
                        second_outcome,
                        true,
                        false,
                    ),
                    source,
                }),
                Err(rollback) => Err(XfrmBidirectionalInstallError::SecondInstallRollbackFailed {
                    outcome: XfrmBidirectionalInstallOutcome::second_failed(
                        second_outcome,
                        false,
                        true,
                    ),
                    source,
                    rollback,
                }),
            };
        }
    };

    Ok(XfrmBidirectionalInstallOutcome::applied(
        first_outcome,
        second_outcome,
    ))
}

/// Rekey an SA plus policy using the SDK-defined composite order.
///
/// Operation order is [`XFRM_COMPOSITE_REKEY_ORDER`]. This helper does not
/// attempt rollback because kernel rekey semantics are backend-specific.
///
/// # Errors
///
/// Returns the backend error from the first failing operation.
pub async fn rekey_sa_policy<B>(
    backend: &B,
    sa: RekeySaRequest,
    policy: RekeyPolicyRequest,
) -> Result<XfrmCompositeOutcome, XfrmError>
where
    B: XfrmBackend + ?Sized,
{
    backend.rekey_sa(sa).await?;
    backend.rekey_policy(policy).await?;
    Ok(XfrmCompositeOutcome::applied())
}

/// Remove policy then SA using the SDK-defined composite order.
///
/// Operation order is [`XFRM_COMPOSITE_REMOVE_ORDER`].
///
/// # Errors
///
/// Returns the backend error from the first failing operation.
pub async fn remove_policy_sa<B>(
    backend: &B,
    policy: RemovePolicyRequest,
    sa: RemoveSaRequest,
) -> Result<XfrmCompositeOutcome, XfrmError>
where
    B: XfrmBackend + ?Sized,
{
    backend.remove_policy(policy).await?;
    backend.remove_sa(sa).await?;
    Ok(XfrmCompositeOutcome::applied())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;

    use super::*;
    use crate::{
        AllocateSpiRequest, IpAddress, PolicyParameters, SaParameters, SpiAllocation, XfrmAction,
        XfrmDirection, XfrmId, XfrmMode, XfrmProbe, XfrmSelector, XfrmTemplate,
    };

    #[derive(Debug, Default)]
    struct FailingCompositeBackend {
        operations: Arc<Mutex<Vec<&'static str>>>,
        install_sa_error: Option<XfrmError>,
        install_policy_error: Option<XfrmError>,
        install_policy_successes_before_failure: Option<usize>,
        install_policy_calls: AtomicUsize,
        remove_sa_error: Option<XfrmError>,
    }

    impl FailingCompositeBackend {
        fn with_policy_failure(remove_sa_error: Option<XfrmError>) -> Self {
            Self {
                install_policy_error: Some(XfrmError::Unavailable),
                remove_sa_error,
                ..Self::default()
            }
        }

        fn with_sa_failure() -> Self {
            Self {
                install_sa_error: Some(XfrmError::Unavailable),
                ..Self::default()
            }
        }

        fn with_second_policy_failure() -> Self {
            Self {
                install_policy_error: Some(XfrmError::Unavailable),
                install_policy_successes_before_failure: Some(1),
                ..Self::default()
            }
        }

        fn record(&self, operation: &'static str) {
            let mut operations = match self.operations.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            operations.push(operation);
        }

        fn operations(&self) -> Vec<&'static str> {
            match self.operations.lock() {
                Ok(guard) => guard.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }
    }

    #[async_trait]
    impl XfrmBackend for FailingCompositeBackend {
        async fn allocate_spi(
            &self,
            _request: AllocateSpiRequest,
        ) -> Result<SpiAllocation, XfrmError> {
            Err(XfrmError::UnsupportedFeature {
                feature: "test allocate_spi",
            })
        }

        async fn install_sa(&self, _request: InstallSaRequest) -> Result<(), XfrmError> {
            self.record("install_sa");
            if let Some(error) = self.install_sa_error.clone() {
                return Err(error);
            }
            Ok(())
        }

        async fn query_sa(
            &self,
            _request: crate::model::QuerySaRequest,
        ) -> Result<crate::model::SaState, XfrmError> {
            Err(XfrmError::UnsupportedFeature {
                feature: "test query_sa",
            })
        }

        async fn rekey_sa(&self, _request: RekeySaRequest) -> Result<(), XfrmError> {
            self.record("rekey_sa");
            Ok(())
        }

        async fn remove_sa(&self, _request: RemoveSaRequest) -> Result<(), XfrmError> {
            self.record("remove_sa");
            if let Some(error) = self.remove_sa_error.clone() {
                return Err(error);
            }
            Ok(())
        }

        async fn install_policy(&self, _request: InstallPolicyRequest) -> Result<(), XfrmError> {
            self.record("install_policy");
            let call_index = self.install_policy_calls.fetch_add(1, Ordering::Relaxed);
            let should_fail = self
                .install_policy_successes_before_failure
                .map_or(self.install_policy_error.is_some(), |successes| {
                    self.install_policy_error.is_some() && call_index >= successes
                });
            if should_fail {
                let error = self
                    .install_policy_error
                    .clone()
                    .unwrap_or(XfrmError::Unavailable);
                return Err(error);
            }
            Ok(())
        }

        async fn rekey_policy(&self, _request: RekeyPolicyRequest) -> Result<(), XfrmError> {
            self.record("rekey_policy");
            Ok(())
        }

        async fn remove_policy(&self, _request: RemovePolicyRequest) -> Result<(), XfrmError> {
            self.record("remove_policy");
            Ok(())
        }

        async fn probe(&self) -> Result<XfrmProbe, XfrmError> {
            Ok(XfrmProbe::mock())
        }
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddress {
        IpAddress::Ipv4([a, b, c, d])
    }

    fn selector() -> XfrmSelector {
        XfrmSelector::new(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 50)
    }

    fn sa_parameters() -> SaParameters {
        SaParameters {
            selector: selector(),
            id: XfrmId {
                destination: ipv4(10, 0, 0, 2),
                spi: 0x1234_5678,
                protocol: 50,
            },
            source_address: ipv4(10, 0, 0, 1),
            request_id: None,
            auth: None,
            crypt: None,
            aead: None,
            mode: XfrmMode::Tunnel,
            lifetime: Default::default(),
            replay_window: 32,
            replay_state: None,
            encap: None,
            mark: None,
            if_id: None,
        }
    }

    fn policy_parameters() -> PolicyParameters {
        PolicyParameters {
            selector: selector(),
            direction: XfrmDirection::Out,
            action: XfrmAction::Allow,
            priority: 100,
            templates: vec![XfrmTemplate {
                id: sa_parameters().id,
                source_address: ipv4(10, 0, 0, 1),
                request_id: None,
                mode: XfrmMode::Tunnel,
            }],
            mark: None,
            if_id: None,
        }
    }

    fn install_request() -> XfrmCompositeInstallRequest {
        XfrmCompositeInstallRequest {
            sa: InstallSaRequest {
                parameters: sa_parameters(),
            },
            policy: InstallPolicyRequest {
                parameters: policy_parameters(),
            },
        }
    }

    #[tokio::test]
    async fn composite_install_applies_sa_then_policy() {
        let backend = FailingCompositeBackend::default();

        let outcome = match install_sa_policy_with_rollback(&backend, install_request()).await {
            Ok(value) => value,
            Err(error) => panic!("composite install failed: {error:?}"),
        };

        assert_eq!(outcome, XfrmCompositeOutcome::applied());
        assert_eq!(backend.operations(), vec!["install_sa", "install_policy"]);
        assert_eq!(
            XFRM_COMPOSITE_INSTALL_ORDER,
            [
                XfrmCompositeOperation::InstallSa,
                XfrmCompositeOperation::InstallPolicy,
            ]
        );
    }

    #[tokio::test]
    async fn composite_install_rolls_back_sa_when_policy_install_fails() {
        let backend = FailingCompositeBackend::with_policy_failure(None);

        let error = match install_sa_policy_with_rollback(&backend, install_request()).await {
            Ok(value) => panic!("policy failure unexpectedly applied: {value:?}"),
            Err(error) => error,
        };

        assert_eq!(error.as_str(), "xfrm_composite_policy_install_rolled_back");
        assert_eq!(
            error.outcome(),
            XfrmCompositeOutcome::rolled_back(XfrmCompositeOperation::InstallPolicy)
        );
        assert_eq!(
            backend.operations(),
            vec!["install_sa", "install_policy", "remove_sa"]
        );
    }

    #[tokio::test]
    async fn composite_install_reports_partial_state_when_rollback_fails() {
        let backend = FailingCompositeBackend::with_policy_failure(Some(XfrmError::NotFound));

        let error = match install_sa_policy_with_rollback(&backend, install_request()).await {
            Ok(value) => panic!("rollback failure unexpectedly applied: {value:?}"),
            Err(error) => error,
        };

        assert_eq!(
            error.as_str(),
            "xfrm_composite_policy_install_rollback_failed"
        );
        let outcome = error.outcome();
        assert!(outcome.rollback_failed);
        assert!(outcome.partial_state_possible);
        assert_eq!(
            backend.operations(),
            vec!["install_sa", "install_policy", "remove_sa"]
        );
    }

    #[tokio::test]
    async fn composite_install_sa_failure_does_not_attempt_policy_or_rollback() {
        let backend = FailingCompositeBackend::with_sa_failure();

        let error = match install_sa_policy_with_rollback(&backend, install_request()).await {
            Ok(value) => panic!("SA failure unexpectedly applied: {value:?}"),
            Err(error) => error,
        };

        assert_eq!(error.as_str(), "xfrm_composite_install_sa_failed");
        assert_eq!(
            error.outcome(),
            XfrmCompositeOutcome::not_applied(XfrmCompositeOperation::InstallSa)
        );
        assert_eq!(backend.operations(), vec!["install_sa"]);
    }

    #[tokio::test]
    async fn composite_rekey_and_remove_use_stable_order() {
        let backend = FailingCompositeBackend::default();
        let sa = sa_parameters();
        let policy = policy_parameters();

        let rekey = rekey_sa_policy(
            &backend,
            RekeySaRequest {
                parameters: sa.clone(),
            },
            RekeyPolicyRequest {
                parameters: policy.clone(),
            },
        )
        .await;
        match rekey {
            Ok(outcome) => assert_eq!(outcome, XfrmCompositeOutcome::applied()),
            Err(error) => panic!("rekey composite failed: {error:?}"),
        }

        let remove = remove_policy_sa(
            &backend,
            RemovePolicyRequest {
                selector: policy.selector,
                direction: policy.direction,
            },
            RemoveSaRequest {
                destination: sa.id.destination,
                protocol: sa.id.protocol,
                spi: sa.id.spi,
            },
        )
        .await;
        match remove {
            Ok(outcome) => assert_eq!(outcome, XfrmCompositeOutcome::applied()),
            Err(error) => panic!("remove composite failed: {error:?}"),
        }
        assert_eq!(
            backend.operations(),
            vec!["rekey_sa", "rekey_policy", "remove_policy", "remove_sa"]
        );
    }

    #[tokio::test]
    async fn bidirectional_install_rolls_back_first_direction_when_second_fails() {
        let backend = FailingCompositeBackend::with_second_policy_failure();

        let error = match install_bidirectional_sa_policy_with_rollback(
            &backend,
            [install_request(), install_request()],
        )
        .await
        {
            Ok(value) => panic!("bidirectional install unexpectedly applied: {value:?}"),
            Err(error) => error,
        };

        assert_eq!(
            error.as_str(),
            "xfrm_bidirectional_second_install_rolled_back"
        );
        let outcome = error.outcome();
        assert!(outcome.cross_rolled_back);
        assert!(!outcome.cross_rollback_failed);
        assert!(!outcome.partial_state_possible);
        assert_eq!(
            backend.operations(),
            vec![
                "install_sa",
                "install_policy",
                "install_sa",
                "install_policy",
                "remove_sa",
                "remove_policy",
                "remove_sa"
            ]
        );
    }
}
