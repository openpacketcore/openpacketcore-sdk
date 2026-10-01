//! Keep the original thirty-second storage deadline across native apply pages.

use std::io;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;

#[derive(Debug, Default)]
pub(super) struct ApplyPrefixDeadline {
    prefix: Mutex<Option<(u64, Instant)>>,
}

impl ApplyPrefixDeadline {
    pub(super) fn deadline(&self, committed: Option<u64>, now: Instant) -> io::Result<Instant> {
        let fresh = now
            .checked_add(Duration::from_secs(30))
            .ok_or_else(|| io::Error::other("config apply deadline overflow"))?;
        let Some(upto) = committed else {
            // Direct storage calls without a committed frontier retain the
            // original per-call deadline. Native replay has a loaded frontier.
            return Ok(fresh);
        };
        let mut prefix = self
            .prefix
            .lock()
            .map_err(|_| io::Error::other("config apply deadline unavailable"))?;
        let (_, deadline) = prefix.get_or_insert((upto, fresh));
        Ok(*deadline)
    }

    pub(super) fn applied(&self, index: u64) -> io::Result<()> {
        let mut prefix = self
            .prefix
            .lock()
            .map_err(|_| io::Error::other("config apply deadline unavailable"))?;
        if prefix.as_ref().is_some_and(|(upto, _)| index >= *upto) {
            *prefix = None;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_apply_pages_keep_original_deadline_until_committed_frontier() {
        let budget = ApplyPrefixDeadline::default();
        let start = Instant::now();
        let original = budget.deadline(Some(1024), start).unwrap();
        assert_eq!(original, start + Duration::from_secs(30));
        budget.applied(63).unwrap();
        // A later commit and another page cannot refresh accepted work's clock.
        assert_eq!(
            budget
                .deadline(Some(2048), start + Duration::from_secs(29))
                .unwrap(),
            original
        );
        budget.applied(1023).unwrap();
        assert_eq!(
            budget
                .deadline(Some(2048), start + Duration::from_secs(31))
                .unwrap(),
            original
        );
        budget.applied(1024).unwrap();
        assert_eq!(
            budget
                .deadline(Some(2048), start + Duration::from_secs(31))
                .unwrap(),
            start + Duration::from_secs(61)
        );
    }

    #[test]
    fn capacity_direct_apply_without_committed_frontier_retains_per_call_budget() {
        let budget = ApplyPrefixDeadline::default();
        let start = Instant::now();
        assert_eq!(
            budget.deadline(None, start).unwrap(),
            start + Duration::from_secs(30)
        );
        assert!(budget.prefix.lock().unwrap().is_none());
    }

    // A real retained native-WAL component, below the still-closed public
    // profile constructor. This is not engine scheduling or cluster proof.
    struct NativePages {
        backend: crate::SqliteBackend,
        log: super::super::SqliteConfigLogStore,
        machine: super::super::SqliteConfigStateMachine,
        progress: std::sync::Arc<super::super::ConfigDurableProgress>,
    }

    fn identity() -> opc_consensus::ConsensusIdentity {
        opc_consensus::ConsensusIdentity::new(
            opc_consensus::ConsensusClusterId::from_bytes([0xD1; 32]),
            opc_consensus::ConsensusConfigurationId::from_bytes([0xD2; 32]),
            opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
        )
    }

    fn log_id(index: u64) -> opc_consensus::engine::LogId<opc_consensus::ConsensusNodeId> {
        opc_consensus::engine::LogId::new(
            opc_consensus::engine::CommittedLeaderId::new(
                1,
                opc_consensus::ConsensusNodeId::new(1).unwrap(),
            ),
            index,
        )
    }

    fn blank(index: u64) -> opc_consensus::engine::Entry<crate::consensus::ConfigRaftTypeConfig> {
        opc_consensus::engine::Entry {
            log_id: log_id(index),
            payload: opc_consensus::engine::EntryPayload::Blank,
        }
    }

    impl NativePages {
        async fn new() -> Self {
            use opc_consensus::engine::storage::RaftLogStorage;
            let scratch = std::env::var_os("TMPDIR").expect("explicit disk scratch root");
            let root = tempfile::Builder::new()
                .prefix("config-capacity-apply-deadline-")
                .tempdir_in(scratch)
                .expect("private retained native fixture")
                .keep();
            let filesystem = std::process::Command::new("findmnt")
                .args(["-n", "-o", "FSTYPE", "-T"])
                .arg(&root)
                .output()
                .expect("disk filesystem detector");
            assert!(filesystem.status.success());
            let filesystem = std::str::from_utf8(&filesystem.stdout).unwrap().trim();
            assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));
            let local = opc_consensus::ConsensusNodeId::new(1).unwrap();
            let members = std::collections::BTreeSet::from([local]);
            let topology = crate::consensus::ConfigConsensusTopology::try_new(
                identity(),
                local,
                members.clone(),
            )
            .unwrap();
            let profile = opc_crypto::ConfigCapacityProfile::BoundedV1;
            let binding = crate::RetainedConfigBinding::new(topology, [0xD3; 32], [0xD4; 32])
                .unwrap()
                .with_capacity_profile(profile);
            let options = crate::RetainedConfigOptions::new(
                root.join("config.sqlite"),
                binding,
                crate::RetainedConfigDurability::Durable {
                    min_free_bytes: 128 * 1024 * 1024,
                },
                256 * 1024 * 1024,
                opc_consensus::DURABLE_CONSENSUS_OPERATION_TIMEOUT,
            )
            .unwrap();
            let backend = crate::SqliteBackend::provision_config_authority(
                options,
                crate::AuditKey::new([0xD5; 32]).unwrap(),
            )
            .await
            .expect("native retained backend");
            let (mut log, machine, progress) = super::super::open(
                &backend,
                root.join("snapshots"),
                identity(),
                members.clone(),
            )
            .await
            .expect("native storage adapters");
            log.core
                .run_sqlite(move |conn| {
                    super::super::sqlite::append_logs_sync(
                        conn,
                        identity(),
                        &members,
                        &[blank(0), blank(1), blank(2)],
                        profile,
                    )
                })
                .await
                .expect("native durable log prefix");
            log.save_committed(Some(log_id(1)))
                .await
                .expect("durable committed frontier");
            Self {
                backend,
                log,
                machine,
                progress,
            }
        }

        async fn observations(
            &self,
        ) -> (
            Option<opc_consensus::engine::LogId<opc_consensus::ConsensusNodeId>>,
            i64,
        ) {
            let conn = self.backend.conn().lock_owned().await;
            assert!(crate::schema::verify_wal_mode(&conn).unwrap());
            assert!(crate::schema::verify_synchronous_extra(&conn).unwrap());
            (
                super::super::sqlite::read_applied_sync(&conn, identity()).unwrap(),
                conn.query_row("SELECT total_changes()", [], |row| row.get(0))
                    .unwrap(),
            )
        }

        async fn close(self) {
            let Self {
                backend,
                log,
                machine,
                progress,
            } = self;
            drop(log);
            drop(machine);
            progress
                .wait_for_storage_release()
                .await
                .expect("native owners released");
            drop(backend);
        }
    }

    #[tokio::test]
    async fn capacity_native_apply_pages_clear_deadline_only_at_original_frontier() {
        use opc_consensus::engine::storage::{RaftLogStorage, RaftStateMachine};
        let mut pages = NativePages::new().await;
        assert_eq!(pages.machine.apply([blank(0)]).await.unwrap().len(), 1);
        let original = pages
            .progress
            .apply_deadline
            .prefix
            .lock()
            .unwrap()
            .unwrap();
        assert_eq!(original.0, 1);
        assert_eq!(pages.observations().await.0, Some(log_id(0)));
        pages.log.save_committed(Some(log_id(2))).await.unwrap();
        assert_eq!(
            *pages.progress.apply_deadline.prefix.lock().unwrap(),
            Some(original)
        );
        assert_eq!(pages.machine.apply([blank(1)]).await.unwrap().len(), 1);
        assert!(pages
            .progress
            .apply_deadline
            .prefix
            .lock()
            .unwrap()
            .is_none());
        assert_eq!(pages.machine.apply([blank(2)]).await.unwrap().len(), 1);
        assert_eq!(pages.observations().await.0, Some(log_id(2)));
        assert!(pages
            .progress
            .apply_deadline
            .prefix
            .lock()
            .unwrap()
            .is_none());
        pages.close().await;
    }

    #[tokio::test]
    async fn capacity_native_apply_expired_prefix_rejects_later_page_before_sql_effects() {
        use opc_consensus::engine::storage::{RaftLogStorage, RaftStateMachine};
        let mut pages = NativePages::new().await;
        assert_eq!(pages.machine.apply([blank(0)]).await.unwrap().len(), 1);
        pages.log.save_committed(Some(log_id(2))).await.unwrap();
        let before = pages.observations().await;
        assert_eq!(before.0, Some(log_id(0)));
        // Deterministic clock injection: test real worker rejection with an
        // expired original frontier, without sleeping or changing production
        // deadlines. This is not a thirty-second wall-clock measurement.
        let expired = Instant::now() - Duration::from_secs(1);
        {
            let mut prefix = pages.progress.apply_deadline.prefix.lock().unwrap();
            assert_eq!(prefix.as_ref().unwrap().0, 1);
            prefix.as_mut().unwrap().1 = expired;
        }
        let rejected = pages.machine.apply([blank(1)]).await.is_err();
        let after = pages.observations().await;
        let retained = *pages.progress.apply_deadline.prefix.lock().unwrap();
        let committed = pages.log.read_committed().await.unwrap();
        pages.close().await;
        assert!(
            rejected,
            "CONFIG_CAPACITY_APPLY_DEADLINE: a later page cannot refresh expired accepted work"
        );
        assert_eq!(after, before, "expired page must have no SQL effects");
        assert_eq!(committed, Some(log_id(2)));
        assert_eq!(retained, Some((1, expired)));
    }
}
