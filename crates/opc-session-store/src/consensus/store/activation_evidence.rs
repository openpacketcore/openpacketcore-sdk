//! Passive evidence for one capability-activation invocation.
//!
//! The observer polls the original future. It adds no operation, deadline,
//! retry, or authority check, and retains neither identities nor error bodies.

use std::cell::Cell;
use std::future::Future;

use crate::StoreError;

/// Closed failure boundaries in the caller's activation path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityActivationFailureStageForTest {
    /// The initial local application-traffic authority check failed.
    InitialAuthority,
    /// Reading the initial cluster scope failed.
    InitialScope,
    /// Discovering the current leader failed.
    LeaderDiscovery,
    /// The local authority check immediately before remote transmission failed.
    PreTransmitAuthority,
    /// The remote call failed after the request may have been transmitted.
    AfterTransmission,
    /// An authenticated peer rejected the activation request.
    AuthenticatedRejection,
    /// Refreshing the leader route failed.
    RouteRefresh,
    /// The local leader returned an activation error.
    LocalLeaderRejected,
    /// The remote leader returned an activation error without its internal stage.
    RemoteLeaderRejected,
    /// Waiting for the activation reply's applied log index failed.
    AppliedIndex,
    /// The local authority check after observing the applied log index failed.
    PostApplyAuthority,
    /// Reading the cluster scope after observing the applied log index failed.
    PostApplyScope,
    /// The backend could not check the persisted activation certificate.
    CertificateBackend,
    /// No persisted activation certificate matched the current cluster scope.
    CertificateMismatch,
    /// The leader reported an unknown activation outcome.
    OutcomeUnknown,
    /// The activation request received a reply for another mutation operation.
    UnexpectedReply,
}

impl CapabilityActivationFailureStageForTest {
    /// A fixed, body-free tag suitable for bounded qualification diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InitialAuthority => "initial_authority",
            Self::InitialScope => "initial_scope",
            Self::LeaderDiscovery => "leader_discovery",
            Self::PreTransmitAuthority => "pre_transmit_authority",
            Self::AfterTransmission => "after_transmission",
            Self::AuthenticatedRejection => "authenticated_rejection",
            Self::RouteRefresh => "route_refresh",
            Self::LocalLeaderRejected => "local_leader_rejected",
            Self::RemoteLeaderRejected => "remote_leader_rejected",
            Self::AppliedIndex => "applied_index",
            Self::PostApplyAuthority => "post_apply_authority",
            Self::PostApplyScope => "post_apply_scope",
            Self::CertificateBackend => "certificate_backend",
            Self::CertificateMismatch => "certificate_mismatch",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::UnexpectedReply => "unexpected_reply",
        }
    }
}

/// Evidence recorded at the actual error return, not inferred from elapsed
/// wall time or a later health probe. A remote rejection does not identify the
/// failed stage inside the remote handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityActivationFailureForTest {
    /// The caller boundary where the original activation error was returned.
    pub stage: CapabilityActivationFailureStageForTest,
    /// Whether this invocation's original deadline had elapsed at rejection.
    /// This does not assert that deadline exhaustion caused the rejection.
    pub deadline_elapsed: bool,
}

tokio::task_local! {
    static FAILURE: Cell<Option<CapabilityActivationFailureForTest>>;
}

#[cfg(test)]
tokio::task_local! {
    pub(super) static READ_ADMIT_GATE: std::sync::Arc<crate::consensus::snapshot::SnapshotArtifactGate>;
}

#[cfg(test)]
pub(super) async fn after_read_admit() {
    if let Ok(gate) = READ_ADMIT_GATE.try_with(std::sync::Arc::clone) {
        gate.block_if_armed().await;
    }
}

/// Observe the existing activation future without changing its result.
/// Concurrent, nested, and subsequent scopes cannot reuse this observation.
pub async fn observe_capability_activation_for_test(
    activation: impl Future<Output = Result<(), StoreError>>,
) -> (
    Result<(), StoreError>,
    Option<CapabilityActivationFailureForTest>,
) {
    FAILURE
        .scope(Cell::new(None), async {
            let result = activation.await;
            let failure = result.as_ref().err().and_then(|_| FAILURE.with(Cell::get));
            (result, failure)
        })
        .await
}

pub(super) fn record(
    stage: CapabilityActivationFailureStageForTest,
    deadline: tokio::time::Instant,
    error: StoreError,
) -> StoreError {
    let _ = FAILURE.try_with(|failure| {
        if failure.get().is_none() {
            failure.set(Some(CapabilityActivationFailureForTest {
                stage,
                deadline_elapsed: tokio::time::Instant::now() >= deadline,
            }));
        }
    });
    error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn activation_evidence_is_scoped_to_concurrent_nested_and_next_attempts() {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        let first = observe_capability_activation_for_test(async {
            let error = record(
                CapabilityActivationFailureStageForTest::InitialAuthority,
                deadline,
                StoreError::BackendUnavailable("first-sensitive-body".to_owned()),
            );
            tokio::task::yield_now().await;
            let nested = observe_capability_activation_for_test(async {
                Err(record(
                    CapabilityActivationFailureStageForTest::CertificateMismatch,
                    deadline,
                    StoreError::BackendUnavailable("nested-sensitive-body".to_owned()),
                ))
            })
            .await;
            assert_eq!(
                nested.1.unwrap().stage,
                CapabilityActivationFailureStageForTest::CertificateMismatch
            );
            Err(error)
        });
        let second = observe_capability_activation_for_test(async {
            tokio::task::yield_now().await;
            Err(record(
                CapabilityActivationFailureStageForTest::AfterTransmission,
                deadline,
                StoreError::BackendUnavailable("second-sensitive-body".to_owned()),
            ))
        });
        let (first, second) = tokio::join!(first, second);
        assert_eq!(
            first.0,
            Err(StoreError::BackendUnavailable(
                "first-sensitive-body".to_owned()
            ))
        );
        assert_eq!(
            second.0,
            Err(StoreError::BackendUnavailable(
                "second-sensitive-body".to_owned()
            ))
        );
        assert_eq!(
            first.1.unwrap().stage,
            CapabilityActivationFailureStageForTest::InitialAuthority
        );
        assert_eq!(first.1.unwrap().stage.as_str(), "initial_authority");
        assert_eq!(
            second.1.unwrap().stage,
            CapabilityActivationFailureStageForTest::AfterTransmission
        );
        assert!(!format!("{:?} {:?}", first.1, second.1).contains("sensitive-body"));

        let next = observe_capability_activation_for_test(async {
            Err(StoreError::BackendUnavailable("unobserved".to_owned()))
        })
        .await;
        assert!(next.0.is_err());
        assert_eq!(next.1, None, "another attempt supplies no evidence");
        assert_eq!(
            observe_capability_activation_for_test(async { Ok(()) }).await,
            (Ok(()), None)
        );
    }
}
