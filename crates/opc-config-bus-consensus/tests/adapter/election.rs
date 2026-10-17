//! Deterministic ordinary election after abrupt loss; no manual campaign.

use opc_consensus::test_runtime::{ElectionRngScript, ScriptedElectionRuntime};
use opc_consensus::{durable_openraft_config, DurableOpenraftDomain};
use tokio::time::Instant;

use super::*;

#[path = "../../../opc-consensus/tests/reelection/delivery.rs"]
pub(super) mod delivery;
#[path = "../../../opc-consensus/tests/reelection/schedule.rs"]
pub(super) mod schedule;

pub(super) struct Election {
    pub scripts: [ElectionRngScript; 3],
    started: Instant,
    early: schedule::ElectionSchedule,
    late: schedule::ElectionSchedule,
    delivery: delivery::TickDelivery,
    _guard: tracing::subscriber::DefaultGuard,
}

impl Election {
    pub async fn new() -> Self {
        let (delivery, guard) = delivery::TickDelivery::install();
        let config = durable_openraft_config(DurableOpenraftDomain::ConfigurationState).unwrap();
        let early_sample = 1_u64 << 62;
        let late_sample = 3_u64 << 62;
        let calibration = ElectionRngScript::new([early_sample, late_sample]);
        let (early, late) = calibration
            .scope(async {
                (
                    Duration::from_millis(
                        config.new_rand_election_timeout::<ScriptedElectionRuntime>(),
                    ),
                    Duration::from_millis(
                        config.new_rand_election_timeout::<ScriptedElectionRuntime>(),
                    ),
                )
            })
            .await;
        calibration.assert_exhausted();
        Self {
            scripts: [
                ElectionRngScript::new([late_sample; 2]),
                ElectionRngScript::new([early_sample; 2]),
                ElectionRngScript::new([late_sample; 1]),
            ],
            started: Instant::now(),
            early: schedule::ElectionSchedule::new(&config, early),
            late: schedule::ElectionSchedule::new(&config, late),
            delivery,
            _guard: guard,
        }
    }

    pub async fn elect_survivor(self, cluster: &ProjectionCluster, old_leader: usize) -> usize {
        assert_eq!(old_leader, 0, "canonical initial leader");
        assert_eq!(
            Instant::now(),
            self.started,
            "disk work did not consume protocol time"
        );
        let term = cluster.stores[1].status().term;
        let expected = cluster.stores[1].status().node_id;
        let bound = self.early.campaign(Duration::ZERO, Duration::ZERO, true);
        assert!(bound < self.late.campaign(Duration::ZERO, Duration::ZERO, true));
        for script in &self.scripts[1..] {
            schedule::tick_registered(&mut script.sleeps(), self.started, self.early.tick).await;
        }
        let mut tick = self.early.tick;
        while tick <= bound {
            tokio::time::advance(self.started + tick - Instant::now()).await;
            for (index, script) in self.scripts.iter().enumerate().skip(1) {
                schedule::tick_registered(
                    &mut script.sleeps(),
                    self.started + tick,
                    self.early.tick,
                )
                .await;
                self.delivery
                    .wait(
                        cluster.stores[index].status().node_id.get(),
                        self.started + tick,
                    )
                    .await;
            }
            tick += self.early.tick;
        }
        while !cluster.stores[1..].iter().all(|store| {
            let status = store.status();
            status.leader_id == Some(expected) && status.term == term + 1
        }) {
            tokio::task::yield_now().await;
        }
        assert_eq!(self.started.elapsed(), bound);
        for script in &self.scripts {
            script.finish();
        }
        1
    }
}
