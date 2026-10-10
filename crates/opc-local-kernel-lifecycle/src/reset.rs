use crate::LocalLifecycleError;
#[cfg(test)]
use crate::ResetPhase;
use async_trait::async_trait;

pub(crate) async fn supervise(
    port: &mut impl ResetPort,
    schedule: &std::sync::Mutex<crate::CleanupSchedule>,
) -> Result<(), LocalLifecycleError> {
    use futures_util::FutureExt;
    use std::{panic::AssertUnwindSafe, time::Duration};
    // Refuse an unsupported/foreign graph before any possible containment
    // mutation. Once this preflight succeeds, this owner remains responsible
    // through every uncertain acknowledgement, panic and timed-out attempt.
    std::panic::catch_unwind(AssertUnwindSafe(|| port.inspect()))
        .unwrap_or(Err(LocalLifecycleError::Indeterminate))?;
    loop {
        let next = schedule
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .next_attempt();
        tokio::time::sleep_until(next).await;
        let Some(attempt) = schedule
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .begin()
        else {
            continue;
        };
        port.begin_attempt(attempt);
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            AssertUnwindSafe(run(port)).catch_unwind(),
        )
        .await;
        match result {
            Ok(Ok(Ok(()))) => return Ok(()),
            // The first TCX query precedes containment writes. A kernel without
            // that capability cannot become supported by retrying cleanup.
            Ok(Ok(Err(LocalLifecycleError::Unsupported))) => {
                return Err(LocalLifecycleError::Unsupported);
            }
            _ => {}
        }
        schedule
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .failed(rand::random());
    }
}

#[async_trait]
pub(crate) trait ResetPort: Send {
    fn begin_attempt(&mut self, _attempt: crate::CleanupAttempt) {}
    fn inspect(&mut self) -> Result<(), LocalLifecycleError>;
    fn contain(&mut self) -> Result<(), LocalLifecycleError>;
    fn coverage(&self) -> Result<(), LocalLifecycleError>;
    async fn xfrm(&mut self) -> Result<(), LocalLifecycleError>;
    async fn routes(&mut self) -> Result<(), LocalLifecycleError>;
    async fn companions(&mut self) -> Result<(), LocalLifecycleError>;
    fn artifacts(&mut self) -> Result<(), LocalLifecycleError>;
    async fn verify(&mut self) -> Result<(), LocalLifecycleError>;
}

pub(crate) async fn run(port: &mut impl ResetPort) -> Result<(), LocalLifecycleError> {
    port.inspect()?;
    port.contain()?;
    port.coverage()?;
    port.xfrm().await?;
    port.coverage()?;
    port.routes().await?;
    port.coverage()?;
    port.companions().await?;
    port.coverage()?;
    port.artifacts()?;
    port.coverage()?;
    port.verify().await?;
    port.coverage()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Port {
        contained: bool,
        retired: [bool; 4],
        event_count: usize,
        cut: Option<usize>,
        coverage_ok: bool,
        verified: bool,
        trace: Vec<ResetPhase>,
        panic_once: bool,
        slow_once: bool,
        unsupported: bool,
    }
    impl Port {
        fn new() -> Self {
            Self {
                contained: false,
                retired: [false; 4],
                event_count: 0,
                cut: None,
                coverage_ok: true,
                verified: false,
                trace: Vec::new(),
                panic_once: false,
                slow_once: false,
                unsupported: false,
            }
        }
        fn event(&mut self, phase: ResetPhase) -> Result<(), LocalLifecycleError> {
            self.trace.push(phase);
            self.event_count += 1;
            if self.cut == Some(self.event_count) {
                Err(LocalLifecycleError::Incomplete(phase))
            } else {
                Ok(())
            }
        }
        fn retire(&mut self, index: usize, phase: ResetPhase) -> Result<(), LocalLifecycleError> {
            assert!(
                self.contained,
                "plaintext must be blocked before a protective effect is removed"
            );
            assert!(
                self.retired[..index].iter().all(|retired| *retired),
                "a preceding owner has not completed cleanup"
            );
            self.retired[index] = true;
            self.event(phase)
        }
    }
    #[async_trait]
    impl ResetPort for Port {
        fn inspect(&mut self) -> Result<(), LocalLifecycleError> {
            self.event(ResetPhase::Inspect)
        }
        fn contain(&mut self) -> Result<(), LocalLifecycleError> {
            if self.unsupported {
                return Err(opc_linux_gtpu_sys::tc::ScopeError::Unsupported.into());
            }
            self.contained = true;
            self.event(ResetPhase::Contain)
        }
        fn coverage(&self) -> Result<(), LocalLifecycleError> {
            if self.contained && self.coverage_ok {
                Ok(())
            } else {
                Err(LocalLifecycleError::Incomplete(ResetPhase::Contain))
            }
        }
        async fn xfrm(&mut self) -> Result<(), LocalLifecycleError> {
            if std::mem::take(&mut self.panic_once) {
                panic!("injected reset panic after containment");
            }
            if std::mem::take(&mut self.slow_once) {
                tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            }
            self.retire(0, ResetPhase::Xfrm)
        }
        async fn routes(&mut self) -> Result<(), LocalLifecycleError> {
            self.retire(1, ResetPhase::Routes)
        }
        async fn companions(&mut self) -> Result<(), LocalLifecycleError> {
            self.retire(2, ResetPhase::Companions)
        }
        fn artifacts(&mut self) -> Result<(), LocalLifecycleError> {
            self.retire(3, ResetPhase::Artifacts)
        }
        async fn verify(&mut self) -> Result<(), LocalLifecycleError> {
            assert!(self.contained && self.retired == [true; 4]);
            self.event(ResetPhase::Verify)?;
            self.verified = true;
            Ok(())
        }
    }

    #[tokio::test]
    async fn all_protection_and_companion_phases_precede_graph_rebuild() {
        let mut port = Port::new();
        run(&mut port).await.unwrap();
        assert!(port.verified);
        assert_eq!(
            port.trace,
            [
                ResetPhase::Inspect,
                ResetPhase::Contain,
                ResetPhase::Xfrm,
                ResetPhase::Routes,
                ResetPhase::Companions,
                ResetPhase::Artifacts,
                ResetPhase::Verify
            ]
        );
    }

    #[tokio::test]
    async fn every_interruption_withholds_rebuild_and_a_fresh_reset_converges() {
        for cut in 1..=7 {
            let mut port = Port::new();
            port.cut = Some(cut);
            assert!(run(&mut port).await.is_err());
            assert!(!port.verified);
            assert_eq!(port.event_count, cut);
            port.cut = None;
            run(&mut port).await.unwrap();
            assert!(port.verified);
        }
    }

    #[tokio::test]
    async fn changed_containment_blocks_xfrm_even_if_old_contain_succeeded() {
        let mut port = Port::new();
        port.coverage_ok = false;
        assert!(run(&mut port).await.is_err());
        assert_eq!(port.retired, [false; 4]);
        assert_eq!(port.trace, [ResetPhase::Inspect, ResetPhase::Contain]);
    }
    #[tokio::test(start_paused = true)]
    async fn supervision_keeps_uncertain_reset_and_paces_fresh_inventory_retry() {
        let mut port = Port::new();
        port.cut = Some(3);
        let schedule = std::sync::Mutex::new(crate::CleanupSchedule::default());
        supervise(&mut port, &schedule).await.unwrap();
        assert!(port.verified);
        assert!(
            port.trace
                .iter()
                .filter(|phase| **phase == ResetPhase::Inspect)
                .count()
                >= 2
        );
        let progress = schedule.lock().unwrap().progress();
        assert_eq!(progress.attempts, 2);
        assert!(progress.first_failure_age.unwrap() >= std::time::Duration::from_millis(50));
    }
    #[tokio::test(start_paused = true)]
    async fn supervision_catches_panic_and_bounds_each_reset_attempt() {
        for panic in [true, false] {
            let mut port = Port::new();
            port.panic_once = panic;
            port.slow_once = !panic;
            let schedule = std::sync::Mutex::new(crate::CleanupSchedule::default());
            let start = tokio::time::Instant::now();
            supervise(&mut port, &schedule).await.unwrap();
            assert!(port.verified);
            assert_eq!(schedule.lock().unwrap().progress().attempts, 2);
            let elapsed = start.elapsed();
            assert!(elapsed < std::time::Duration::from_secs(11));
            if !panic {
                assert!(elapsed >= std::time::Duration::from_secs(10));
            }
        }
    }
    #[tokio::test(start_paused = true)]
    async fn preflight_refusal_has_no_containment_effect_or_retry_owner() {
        let mut port = Port::new();
        port.cut = Some(1);
        let schedule = std::sync::Mutex::new(crate::CleanupSchedule::default());
        assert!(supervise(&mut port, &schedule).await.is_err());
        assert!(!port.contained);
        assert_eq!(schedule.lock().unwrap().progress().attempts, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn unsupported_kernel_is_terminal_before_containment_or_cleanup_retry() {
        let mut port = Port::new();
        port.unsupported = true;
        let schedule = std::sync::Mutex::new(crate::CleanupSchedule::default());
        assert_eq!(
            supervise(&mut port, &schedule).await,
            Err(LocalLifecycleError::Unsupported)
        );
        assert_eq!(port.trace, [ResetPhase::Inspect, ResetPhase::Inspect]);
        assert!(!port.contained);
        assert_eq!(port.retired, [false; 4]);
        let progress = schedule.lock().unwrap().progress();
        assert_eq!(progress.attempts, 1);
        assert_eq!(progress.first_failure_age, None);
        assert_eq!(
            LocalLifecycleError::from(opc_linux_gtpu_sys::tc::ScopeError::Inspection),
            LocalLifecycleError::Scope(opc_linux_gtpu_sys::tc::ScopeError::Inspection)
        );
    }
}

#[cfg(test)]
mod unsupported_tcx_tests {
    use super::*;
    struct TcxFirstSeenByContain {
        contains: usize,
    }
    #[async_trait]
    impl ResetPort for TcxFirstSeenByContain {
        fn inspect(&mut self) -> Result<(), LocalLifecycleError> {
            Ok(())
        }
        fn contain(&mut self) -> Result<(), LocalLifecycleError> {
            self.contains += 1;
            Err(opc_linux_gtpu_sys::tc::ScopeError::Unsupported.into())
        }
        fn coverage(&self) -> Result<(), LocalLifecycleError> {
            Ok(())
        }
        async fn xfrm(&mut self) -> Result<(), LocalLifecycleError> {
            Ok(())
        }
        async fn routes(&mut self) -> Result<(), LocalLifecycleError> {
            Ok(())
        }
        async fn companions(&mut self) -> Result<(), LocalLifecycleError> {
            Ok(())
        }
        fn artifacts(&mut self) -> Result<(), LocalLifecycleError> {
            Ok(())
        }
        async fn verify(&mut self) -> Result<(), LocalLifecycleError> {
            Ok(())
        }
    }
    #[tokio::test(start_paused = true)]
    async fn unsupported_tcx_found_by_containment_is_terminal() {
        let mut port = TcxFirstSeenByContain { contains: 0 };
        let schedule = std::sync::Mutex::new(crate::CleanupSchedule::default());
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(600),
            supervise(&mut port, &schedule),
        )
        .await;
        assert_eq!(
            outcome.ok(),
            Some(Err(LocalLifecycleError::Unsupported)),
            "contain() saw Unsupported {} times in 600 virtual seconds and reset kept retrying",
            port.contains
        );
        assert_eq!(port.contains, 1);
        let progress = schedule.lock().unwrap().progress();
        assert_eq!(progress.attempts, 1);
        assert_eq!(progress.first_failure_age, None);
    }
}
