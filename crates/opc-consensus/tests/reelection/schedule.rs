use std::future::Future;
use std::time::Duration;

use opc_consensus::engine::Config;
use tokio::time::Instant;

/// Timer arithmetic for a finite, explicitly controlled election schedule.
pub struct ElectionSchedule {
    pub tick: Duration,
    pub lease: Duration,
    pub sampled_timeout: Duration,
}

/// Keep real I/O from advancing paused protocol time. The real-time watchdog
/// bounds a stuck fixture independently of the election schedule.
pub async fn with_frozen_time<F: Future>(operation: F) -> F::Output {
    let (release, held) = std::sync::mpsc::channel::<()>();
    let mut watchdog =
        tokio::task::spawn_blocking(move || held.recv_timeout(Duration::from_secs(30)));
    let output = tokio::select! {
        output = operation => output,
        result = &mut watchdog => {
            panic!("scripted election wall-clock watchdog expired: {result:?}");
        }
    };
    tokio::time::resume();
    drop(release);
    let _ = watchdog.await.expect("retire election watchdog");
    output
}

/// Wait until the real runtime registers the next tick at the expected phase.
pub async fn tick_registered(
    sleeps: &mut tokio::sync::watch::Receiver<Vec<(Instant, Instant)>>,
    at: Instant,
    tick: Duration,
) {
    sleeps
        .wait_for(|sleeps| sleeps.contains(&(at, at + tick)))
        .await
        .expect("node tick registration");
}

impl ElectionSchedule {
    pub fn new(config: &Config, sampled_timeout: Duration) -> Self {
        assert!(sampled_timeout >= Duration::from_millis(config.election_timeout_min));
        assert!(sampled_timeout < Duration::from_millis(config.election_timeout_max));
        Self {
            tick: Duration::from_millis(config.heartbeat_interval * 3 / 2)
                .min(Duration::from_millis(100)),
            lease: Duration::from_millis(config.election_timeout_max),
            sampled_timeout,
        }
    }

    /// A committed vote carries the leader lease; a split self-vote does not.
    pub fn campaign(
        &self,
        last_vote: Duration,
        ticker_started: Duration,
        committed: bool,
    ) -> Duration {
        let lease = if committed {
            self.lease
        } else {
            Duration::ZERO
        };
        self.round_to_tick(last_vote + lease + self.sampled_timeout, ticker_started)
    }

    fn round_to_tick(&self, deadline: Duration, ticker_started: Duration) -> Duration {
        let ticks = deadline
            .saturating_sub(ticker_started)
            .as_nanos()
            .div_ceil(self.tick.as_nanos())
            .max(1);
        ticker_started + self.tick * u32::try_from(ticks).expect("finite test schedule")
    }
}
