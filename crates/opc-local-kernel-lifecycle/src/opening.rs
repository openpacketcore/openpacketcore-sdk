//! Activation-bound opening and cancellation decisions. The native owner keeps
//! this progress outside every cancellable attempt and retries closure.

use crate::LocalLifecycleError as Error;

#[derive(Default)]
pub(crate) struct Progress {
    pub(crate) started: bool,
    pub(crate) undo: bool,
    pub(crate) published: bool,
    pub(crate) closed: bool,
    pub(crate) failure: Option<Error>,
}
impl Progress {
    pub(crate) fn failed(&mut self, error: Error) {
        if !self.published {
            self.undo = true;
            self.failure.get_or_insert(match error {
                Error::Scope(opc_linux_gtpu_sys::tc::ScopeError::AttemptExpired) => {
                    Error::OpeningAttemptExpired
                }
                other => other,
            });
        }
    }
}
#[async_trait::async_trait]
pub(crate) trait Port: Send {
    async fn current(&self) -> Result<(), Error>;
    fn local(&self) -> Result<(), Error>;
    fn publication(&mut self) -> Result<(), Error>;
    fn covered(&self) -> Result<(), Error>;
    fn open_next(&mut self) -> Result<bool, Error>;
    fn is_open(&self) -> Result<bool, Error>;
    fn contain(&mut self) -> Result<(), Error>;
}

pub(crate) async fn bounded_attempt(
    port: &mut impl Port,
    progress: &mut Progress,
    observer_closed: impl Fn() -> bool,
) -> Result<(), Error> {
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        attempt(port, progress, observer_closed),
    )
    .await
    .unwrap_or(Err(Error::OpeningAttemptExpired));
    if let Err(error) = result {
        progress.failed(error);
    }
    result
}

async fn attempt(
    port: &mut impl Port,
    progress: &mut Progress,
    observer_closed: impl Fn() -> bool,
) -> Result<(), Error> {
    if progress.published || progress.closed {
        return Ok(());
    }
    port.local()?;
    if progress.undo {
        port.contain()?;
        port.covered()?;
        progress.closed = true;
        return Ok(());
    }
    if !progress.started {
        port.covered()?;
    }
    loop {
        if observer_closed() {
            return Err(Error::Indeterminate);
        }
        port.current().await?;
        port.local()?;
        progress.started = true;
        if port.open_next()? {
            break;
        }
    }
    port.current().await?;
    if !port.is_open()? || observer_closed() {
        return Err(Error::Indeterminate);
    }
    port.publication()?;
    progress.published = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Model {
        filters: usize,
        current: bool,
        lost_ack: bool,
        closure_fails: bool,
        deletes: usize,
        current_checks: std::sync::atomic::AtomicUsize,
        current_delay: std::time::Duration,
    }
    impl Default for Model {
        fn default() -> Self {
            Self {
                filters: 2,
                current: true,
                lost_ack: false,
                closure_fails: false,
                deletes: 0,
                current_checks: std::sync::atomic::AtomicUsize::new(0),
                current_delay: std::time::Duration::ZERO,
            }
        }
    }
    #[async_trait::async_trait]
    impl Port for Model {
        async fn current(&self) -> Result<(), Error> {
            tokio::time::sleep(self.current_delay).await;
            self.current_checks
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.current {
                Ok(())
            } else {
                Err(Error::Stale)
            }
        }
        fn local(&self) -> Result<(), Error> {
            Ok(())
        }
        fn publication(&mut self) -> Result<(), Error> {
            self.local()
        }
        fn covered(&self) -> Result<(), Error> {
            if self.filters == 2 {
                Ok(())
            } else {
                Err(Error::Indeterminate)
            }
        }
        fn open_next(&mut self) -> Result<bool, Error> {
            if self.filters == 0 {
                return Ok(true);
            }
            self.filters -= 1;
            self.deletes += 1;
            if self.lost_ack {
                self.lost_ack = false;
                Err(Error::Indeterminate)
            } else {
                Ok(false)
            }
        }
        fn is_open(&self) -> Result<bool, Error> {
            Ok(self.filters == 0)
        }
        fn contain(&mut self) -> Result<(), Error> {
            if self.closure_fails {
                return Err(Error::Indeterminate);
            }
            self.filters = 2;
            Ok(())
        }
    }
    #[tokio::test(start_paused = true)]
    async fn slow_opening_expires_once_then_finishes_only_after_verified_closure() {
        let mut port = Model {
            current_delay: std::time::Duration::from_secs(4),
            ..Default::default()
        };
        let mut progress = Progress::default();
        let began = tokio::time::Instant::now();
        assert_eq!(
            bounded_attempt(&mut port, &mut progress, || false).await,
            Err(Error::OpeningAttemptExpired)
        );
        assert_eq!(began.elapsed(), std::time::Duration::from_secs(10));
        assert_eq!(port.deletes, 2);
        assert!(progress.undo && !progress.published && !progress.closed);
        port.closure_fails = true;
        assert!(bounded_attempt(&mut port, &mut progress, || false)
            .await
            .is_err());
        assert!(!progress.closed);
        port.closure_fails = false;
        bounded_attempt(&mut port, &mut progress, || false)
            .await
            .unwrap();
        assert!(progress.closed && !progress.published);
        assert_eq!(progress.failure, Some(Error::OpeningAttemptExpired));
        assert_eq!(port.filters, 2);
        assert_eq!(
            port.deletes, 2,
            "the supervisor never restarts opening after expiration"
        );
    }
    #[tokio::test]
    async fn every_open_effect_and_publication_requires_current_activation() {
        let mut port = Model::default();
        let mut progress = Progress::default();
        attempt(&mut port, &mut progress, || false).await.unwrap();
        assert!(progress.published && !progress.undo);
        assert_eq!(port.filters, 0);
        assert!(
            port.current_checks
                .load(std::sync::atomic::Ordering::Relaxed)
                >= 3
        );
        let mut stale = Model {
            current: false,
            ..Default::default()
        };
        let mut progress = Progress::default();
        assert!(attempt(&mut stale, &mut progress, || false).await.is_err());
        assert_eq!(stale.deletes, 0);
        assert!(!progress.published);
    }
    #[tokio::test]
    async fn failed_or_cancelled_open_keeps_ownership_until_closure_is_verified() {
        for cancelled in [false, true] {
            let mut port = Model {
                lost_ack: !cancelled,
                ..Default::default()
            };
            let mut progress = Progress::default();
            assert!(attempt(&mut port, &mut progress, || cancelled)
                .await
                .is_err());
            if cancelled {
                assert_eq!(port.deletes, 0, "cancellation precedes the first effect");
            }
            progress.undo = true;
            port.current = false;
            port.closure_fails = true;
            assert!(attempt(&mut port, &mut progress, || true).await.is_err());
            assert!(!progress.closed && !progress.published);
            port.closure_fails = false;
            attempt(&mut port, &mut progress, || true).await.unwrap();
            assert!(progress.closed && !progress.published);
            assert_eq!(port.filters, 2);
        }
    }
}
