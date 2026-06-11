//! Out-of-process drain execution client (GAP-009-006)
//!
//! Uses `operator-lifecycle::drain_upgrade` planning primitives to execute draining
//! sequences via injected asynchronous clients. All executions are idempotent, bounded
//! by deadlines, observable via lifecycle conditions, and redact secrets from error traces.

use async_trait::async_trait;
use operator_lifecycle::{
    ConditionSeverity, ConditionStatus, LifecyclePhase, LifecycleStatus, UpgradeAction,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

#[async_trait]
pub trait NrfClient: Send + Sync {
    async fn deregister(&self) -> Result<(), String>;
}

#[async_trait]
pub trait SessionDrainClient: Send + Sync {
    /// Returns Ok(true) if drain is complete, Ok(false) if still draining, or Err on failure.
    async fn check_drain_status(&self) -> Result<bool, String>;
}

#[async_trait]
pub trait QuorumClient: Send + Sync {
    async fn wait_for_quorum(&self) -> Result<(), String>;
}

#[async_trait]
pub trait WorkloadFenceClient: Send + Sync {
    async fn fence_workload(&self) -> Result<(), String>;
}

/// Out-of-process executor for the network function's session-draining and shutdown phase.
pub struct DrainExecutor<N, S, Q, W> {
    nrf_client: N,
    session_client: S,
    quorum_client: Q,
    fence_client: W,
}

impl<N, S, Q, W> DrainExecutor<N, S, Q, W>
where
    N: NrfClient + 'static,
    S: SessionDrainClient + 'static,
    Q: QuorumClient + 'static,
    W: WorkloadFenceClient + 'static,
{
    pub fn new(nrf_client: N, session_client: S, quorum_client: Q, fence_client: W) -> Self {
        Self {
            nrf_client,
            session_client,
            quorum_client,
            fence_client,
        }
    }

    /// Executes a single UpgradeAction, updating the LifecycleStatus conditions.
    pub async fn execute_action(
        &self,
        action: UpgradeAction,
        status: &mut LifecycleStatus,
        observed_generation: i64,
        timeout: Duration,
        current_time: OffsetDateTime,
    ) -> Result<(), String> {
        // We set the "Draining" condition to True while in progress
        status.set_condition(
            "Draining",
            ConditionStatus::True,
            &format!("{}InProgress", action.as_str()),
            &format!("Executing out-of-process action: {}", action.as_str()),
            observed_generation,
            ConditionSeverity::Info,
            true,
            current_time,
        );

        let fut = async {
            match action {
                UpgradeAction::DeregisterFromNrf => self.nrf_client.deregister().await,
                UpgradeAction::DrainSessions => {
                    let start = std::time::Instant::now();
                    loop {
                        match self.session_client.check_drain_status().await {
                            Ok(true) => return Ok(()),
                            Ok(false) => {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                            Err(e) => return Err(e),
                        }
                        if start.elapsed() > timeout {
                            return Err("Session drain check timed out internally".to_string());
                        }
                    }
                }
                UpgradeAction::WaitForQuorum => self.quorum_client.wait_for_quorum().await,
                UpgradeAction::FenceWorkload => self.fence_client.fence_workload().await,
                _ => Ok(()), // Non-draining actions are no-ops for this executor
            }
        };

        match tokio::time::timeout(timeout, fut).await {
            Ok(Ok(())) => {
                // Success: clear/update condition
                status.set_condition(
                    "Draining",
                    ConditionStatus::False,
                    &format!("{}Completed", action.as_str()),
                    &format!("Successfully completed action: {}", action.as_str()),
                    observed_generation,
                    ConditionSeverity::Info,
                    true,
                    current_time,
                );
                Ok(())
            }
            Ok(Err(err_msg)) => {
                status.set_condition(
                    "Ready",
                    ConditionStatus::False,
                    &format!("{}Failed", action.as_str()),
                    &format!("Action {} failed: {}", action.as_str(), err_msg),
                    observed_generation,
                    ConditionSeverity::Error,
                    true,
                    current_time,
                );
                status.set_phase(LifecyclePhase::Failed);
                let sanitized = operator_lifecycle::sanitize_denial_message(&err_msg);
                Err(sanitized)
            }
            Err(_) => {
                let msg = format!("Action {} timed out after {:?}", action.as_str(), timeout);
                status.set_condition(
                    "Ready",
                    ConditionStatus::False,
                    &format!("{}Timeout", action.as_str()),
                    &msg,
                    observed_generation,
                    ConditionSeverity::Error,
                    true,
                    current_time,
                );
                status.set_phase(LifecyclePhase::Failed);
                Err(msg)
            }
        }
    }

    /// Executes all actions in a plan sequentially. Aborts immediately on first failure.
    pub async fn execute_drain_plan(
        &self,
        actions: &[UpgradeAction],
        status: &mut LifecycleStatus,
        observed_generation: i64,
        per_action_timeout: Duration,
        current_time: OffsetDateTime,
    ) -> Result<(), String> {
        status.set_phase(LifecyclePhase::Draining);

        let mut executed_any = false;
        for &action in actions {
            // Only execute draining actions
            if matches!(
                action,
                UpgradeAction::DeregisterFromNrf
                    | UpgradeAction::DrainSessions
                    | UpgradeAction::WaitForQuorum
                    | UpgradeAction::FenceWorkload
            ) {
                executed_any = true;
                self.execute_action(
                    action,
                    status,
                    observed_generation,
                    per_action_timeout,
                    current_time,
                )
                .await?;
            }
        }

        if !executed_any {
            let msg = "Drain plan contains no executable out-of-process drain actions";
            status.set_condition(
                "Ready",
                ConditionStatus::False,
                "NoDrainActions",
                msg,
                observed_generation,
                ConditionSeverity::Error,
                true,
                current_time,
            );
            status.set_phase(LifecyclePhase::Failed);
            return Err(msg.to_string());
        }

        // If we drained successfully, we can transition to Upgrading
        status.set_phase(LifecyclePhase::Upgrading);
        Ok(())
    }
}

// --- Deterministic Fake Clients for Testing ---

pub struct FakeNrfClient {
    pub should_fail: bool,
    pub error_message: String,
}

#[async_trait]
impl NrfClient for FakeNrfClient {
    async fn deregister(&self) -> Result<(), String> {
        if self.should_fail {
            Err(self.error_message.clone())
        } else {
            Ok(())
        }
    }
}

pub struct FakeSessionDrainClient {
    pub should_fail: bool,
    pub error_message: String,
    pub loops_before_ready: usize,
    counter: Arc<AtomicUsize>,
}

impl FakeSessionDrainClient {
    pub fn new(should_fail: bool, error_message: String, loops_before_ready: usize) -> Self {
        Self {
            should_fail,
            error_message,
            loops_before_ready,
            counter: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl SessionDrainClient for FakeSessionDrainClient {
    async fn check_drain_status(&self) -> Result<bool, String> {
        if self.should_fail {
            return Err(self.error_message.clone());
        }
        let current = self.counter.fetch_add(1, Ordering::SeqCst);
        if current >= self.loops_before_ready {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

pub struct FakeQuorumClient {
    pub should_fail: bool,
    pub error_message: String,
}

#[async_trait]
impl QuorumClient for FakeQuorumClient {
    async fn wait_for_quorum(&self) -> Result<(), String> {
        if self.should_fail {
            Err(self.error_message.clone())
        } else {
            Ok(())
        }
    }
}

pub struct FakeWorkloadFenceClient {
    pub should_fail: bool,
    pub error_message: String,
}

#[async_trait]
impl WorkloadFenceClient for FakeWorkloadFenceClient {
    async fn fence_workload(&self) -> Result<(), String> {
        if self.should_fail {
            Err(self.error_message.clone())
        } else {
            Ok(())
        }
    }
}
