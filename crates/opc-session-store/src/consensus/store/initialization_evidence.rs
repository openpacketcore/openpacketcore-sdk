//! Per-invocation test evidence for existing initialization deadline outcomes.
//!
//! The task-local scope calls the public method and records only the actual
//! elapsed branches. It cannot grant admission, alter an error, extend a
//! deadline, or reuse evidence from another invocation.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DeadlineStage {
    InitializedProbe,
    CanonicalInitialize,
    ExactMembership,
}

#[derive(Clone, Default)]
pub(super) enum ProbeControl {
    #[default]
    Run,
    UntilDeadline,
    Pause {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    },
}

#[derive(Clone, Copy, Debug, Default)]
struct Observation {
    expired: Option<DeadlineStage>,
    probe_active: bool,
    probe_admitted: bool,
    deadline: Option<tokio::time::Instant>,
}

struct Context {
    control: ProbeControl,
    observation: Mutex<Observation>,
}

tokio::task_local! {
    static CURRENT: Arc<Context>;
}

#[derive(Debug)]
pub(super) struct InitializationAttempt {
    pub(super) result: Result<(), ConsensusSessionStoreOpenError>,
    pub(super) cold_on_entry: bool,
    observation: Observation,
}

impl InitializationAttempt {
    pub(super) fn expired_stage(&self) -> Option<DeadlineStage> {
        self.observation.expired
    }

    pub(super) fn probe_was_active_and_unadmitted(&self) -> bool {
        self.observation.probe_active && !self.observation.probe_admitted
    }

    pub(super) fn retryable_recovery_attempt(&self) -> bool {
        matches!(
            self.result,
            Err(ConsensusSessionStoreOpenError::RecoveryRequired)
        ) || (matches!(
            self.result,
            Err(ConsensusSessionStoreOpenError::ClusterFormationRejected)
        ) && self.expired_stage() == Some(DeadlineStage::InitializedProbe)
            && self.probe_was_active_and_unadmitted()
            && self
                .observation
                .deadline
                .is_some_and(|deadline| tokio::time::Instant::now() >= deadline))
    }
}

pub(super) async fn observe(
    store: &ConsensusSessionStore,
    control: ProbeControl,
) -> InitializationAttempt {
    let cold_on_entry = !store.inner.persistence_protocol.is_active();
    let context = Arc::new(Context {
        control,
        observation: Mutex::new(Observation::default()),
    });
    let result = CURRENT
        .scope(Arc::clone(&context), store.initialize_cluster())
        .await;
    let observation = *context.observation.lock().unwrap();
    InitializationAttempt {
        result,
        cold_on_entry,
        observation,
    }
}

pub(super) fn record_deadline(stage: DeadlineStage) {
    let _ = CURRENT.try_with(|context| {
        let mut observation = context.observation.lock().unwrap();
        assert!(
            observation.expired.is_none(),
            "one terminal deadline per attempt"
        );
        observation.expired = Some(stage);
    });
}

pub(super) async fn hold_initialized_probe<T>(
    store: &ConsensusSessionStore,
    deadline: tokio::time::Instant,
    probe: impl Future<Output = T>,
) -> T {
    let control = CURRENT
        .try_with(|context| {
            let mut observation = context.observation.lock().unwrap();
            observation.probe_active = store.inner.persistence_protocol.is_active();
            observation.probe_admitted = store.inner.admitted.load(Ordering::Acquire);
            observation.deadline = Some(deadline);
            context.control.clone()
        })
        .unwrap_or_default();
    match control {
        ProbeControl::Run => {}
        // This hold is inside the unchanged public timeout_at future. It
        // cannot synthesize the elapsed result or restart its deadline.
        ProbeControl::UntilDeadline => std::future::pending::<()>().await,
        ProbeControl::Pause { entered, release } => {
            entered.notify_one();
            release.notified().await;
        }
    }
    probe.await
}
