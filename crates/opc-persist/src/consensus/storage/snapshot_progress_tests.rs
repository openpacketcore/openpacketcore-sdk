//! Large real snapshots with controlled storage latency, independent of host speed.

use std::collections::BTreeSet;
use std::time::Duration;

use opc_consensus::engine::{CommittedLeaderId, EntryPayload, Membership};
use opc_crypto::encrypt_envelope_with_handle_and_nonce;
use opc_key::{
    ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose, Zeroizing, AES_256_GCM_SIV_KEY_LEN,
    AES_256_GCM_SIV_NONCE_LEN,
};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};

use super::*;
use crate::consensus::snapshot_file::test_io::{watchdog, Latency, Phase};
use crate::consensus::{
    ConfigConsensusCommand, ConfigMutationIntent, PreparedConfigCommit,
    CONFIG_CONSENSUS_COMMAND_VERSION,
};
use crate::{AuditKey, CommitRecord, CommitSource};

pub(crate) const PAYLOAD_BYTES: u64 = 8 * 1024 * 1024;

pub(crate) fn large_commands(
    identity: ConsensusIdentity,
    audit_key: &AuditKey,
) -> Vec<ConfigConsensusCommand> {
    let tenant = TenantId::from_static("snapshot-progress-test");
    let handle = KeyHandle::new(
        KeyId::new("snapshot-progress-key").unwrap(),
        KeyPurpose::Config,
        tenant.clone(),
        Zeroizing::new([0x63; AES_256_GCM_SIV_KEY_LEN]),
    );
    let mut parent = None;
    (1_u8..=16)
        .map(|index| {
            let tx_id = TxId::new();
            let committed_at = Timestamp::now_utc();
            let principal =
                "spiffe://test.example/tenant/snapshot-progress-test/ns/core/sa/config".to_owned();
            let schema_digest = SchemaDigest::from_bytes([0x64; 32]);
            let aad = EnvelopeAad::config(
                tenant.clone(),
                u64::from(index),
                ConfigAad::new(
                    tx_id,
                    parent,
                    committed_at,
                    &principal,
                    schema_digest,
                    "running",
                )
                .unwrap(),
            );
            let plaintext = vec![index; 512 * 1024];
            let record = CommitRecord {
                tx_id,
                parent_tx_id: parent,
                version: ConfigVersion::new(u64::from(index)),
                committed_at,
                principal,
                source: CommitSource::Gnmi,
                schema_digest,
                plaintext_digest: Sha256::digest(&plaintext).to_vec(),
                encrypted_blob: encrypt_envelope_with_handle_and_nonce(
                    &handle,
                    &aad,
                    &plaintext,
                    [index; AES_256_GCM_SIV_NONCE_LEN],
                )
                .unwrap(),
                rollback_point: false,
                confirmed_deadline: None,
            };
            parent = Some(tx_id);
            ConfigConsensusCommand {
                schema_version: CONFIG_CONSENSUS_COMMAND_VERSION,
                identity,
                request_id: opc_consensus::ConsensusRequestId::from_bytes([index; 16]),
                logical_time: committed_at,
                intent: ConfigMutationIntent::AppendCommit(Box::new(
                    PreparedConfigCommit::prepare(record, Vec::new(), audit_key).unwrap(),
                )),
            }
        })
        .collect()
}

async fn machine(directory: &Path) -> (SqliteBackend, SqliteConfigStateMachine, ConsensusIdentity) {
    let identity = ConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::new("snapshot-progress").unwrap(),
        opc_consensus::ConsensusConfigurationId::from_bytes([0x65; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let node = ConsensusNodeId::new(1).unwrap();
    let members = BTreeSet::from([node]);
    let backend = SqliteBackend::open_with_audit_key(
        directory.join("config.sqlite"),
        true,
        0,
        AuditKey::new([0x66; 32]).unwrap(),
    )
    .await
    .unwrap();
    let (_, mut machine, _) = open(
        &backend,
        directory.join("snapshots"),
        identity,
        members.clone(),
    )
    .await
    .unwrap();
    machine
        .apply([Entry {
            log_id: LogId::new(CommittedLeaderId::new(1, node), 0),
            payload: EntryPayload::Membership(Membership::new(vec![members.clone()], members)),
        }])
        .await
        .unwrap();
    for (index, command) in large_commands(identity, backend.audit_key())
        .into_iter()
        .enumerate()
    {
        let applied = machine
            .apply([Entry {
                log_id: LogId::new(CommittedLeaderId::new(1, node), index as u64 + 1),
                payload: EntryPayload::Normal(command),
            }])
            .await
            .unwrap();
        assert!(
            applied[0].result.is_ok(),
            "large history fixture: {applied:?}"
        );
    }
    (backend, machine, identity)
}

struct InstallFixture {
    _backend: SqliteBackend,
    log: SqliteConfigLogStore,
    machine: SqliteConfigStateMachine,
    meta: SnapshotMeta<ConsensusNodeId, opc_consensus::engine::EmptyNode>,
    incoming: Box<ConfigSnapshotFile>,
    directory: tempfile::TempDir,
}

async fn install_fixture() -> InstallFixture {
    let source_directory = tempfile::tempdir().unwrap();
    let (_source, mut source, identity) = machine(source_directory.path()).await;
    let snapshot = source
        .get_snapshot_builder()
        .await
        .build_snapshot()
        .await
        .unwrap();
    let bytes = tokio::fs::read(snapshot.snapshot.path()).await.unwrap();
    assert!(bytes.len() as u64 > PAYLOAD_BYTES);
    let directory = tempfile::tempdir().unwrap();
    let backend = SqliteBackend::open_with_audit_key(
        directory.path().join("config.sqlite"),
        true,
        0,
        AuditKey::new([0x66; 32]).unwrap(),
    )
    .await
    .unwrap();
    let (log, mut machine, _) = open(
        &backend,
        directory.path().join("snapshots"),
        identity,
        BTreeSet::from([ConsensusNodeId::new(1).unwrap()]),
    )
    .await
    .unwrap();
    let mut incoming = machine.begin_receiving_snapshot().await.unwrap();
    incoming.write_all(&bytes).await.unwrap();
    InstallFixture {
        directory,
        _backend: backend,
        log,
        machine,
        meta: snapshot.meta,
        incoming,
    }
}

#[tokio::test]
async fn snapshot_progress_received_sync_install_follows_artifact_size() {
    watchdog(async {
        let mut fixture = install_fixture().await;
        let bytes = std::fs::metadata(fixture.incoming.path()).unwrap().len();
        let delay = SNAPSHOT_OPERATION_TIMEOUT + Duration::from_millis(500);
        assert!(delay < snapshot_work_budget(bytes));
        let through = fixture.meta.last_log_id;
        let mut latency = Latency::new(fixture.directory.path(), Phase::Sync);
        let started = tokio::time::Instant::now();
        latency
            .run(
                delay,
                fixture
                    .machine
                    .install_snapshot(&fixture.meta, fixture.incoming),
            )
            .await
            .expect("a whole-file sync within the artifact's size budget must finish");
        assert!(started.elapsed() > SNAPSHOT_OPERATION_TIMEOUT);
        assert_eq!(fixture.machine.applied_state().await.unwrap().0, through);
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_received_sync_install_stays_bounded() {
    watchdog(async {
        let mut fixture = install_fixture().await;
        let bytes = std::fs::metadata(fixture.incoming.path()).unwrap().len();
        let mut latency = Latency::new(fixture.directory.path(), Phase::Sync);
        let result = latency
            .run(
                snapshot_work_budget(bytes) + Duration::from_secs(1),
                fixture
                    .machine
                    .install_snapshot(&fixture.meta, fixture.incoming),
            )
            .await;
        assert!(
            result.is_err(),
            "the size-derived sync budget remains finite"
        );
        assert_eq!(fixture.machine.applied_state().await.unwrap().0, None);
        assert!(fixture
            .machine
            .get_current_snapshot()
            .await
            .unwrap()
            .is_none());
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_purge_waits_for_the_owned_large_install() {
    watchdog(async {
        let mut fixture = install_fixture().await;
        let through = fixture.meta.last_log_id.unwrap();
        let mut latency = Latency::new(fixture.directory.path(), Phase::Read);
        let started = tokio::time::Instant::now();
        let (installed, purged) = latency
            .run(Duration::from_secs(8), async {
                tokio::join!(
                    fixture
                        .machine
                        .install_snapshot(&fixture.meta, fixture.incoming),
                    fixture.log.purge(through),
                )
            })
            .await;
        installed.expect("the progressing large install must finish");
        purged
            .expect("purge must await the bounded install instead of expiring its own fixed timer");
        assert!(started.elapsed() > SNAPSHOT_OPERATION_TIMEOUT);
        assert_eq!(
            fixture.machine.applied_state().await.unwrap().0,
            Some(through)
        );
        assert_eq!(
            fixture
                .log
                .get_log_state()
                .await
                .unwrap()
                .last_purged_log_id,
            Some(through)
        );
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_unrelated_install_does_not_extend_purge() {
    watchdog(async {
        let mut fixture = install_fixture().await;
        let installed_cut = fixture.meta.last_log_id.unwrap();
        let mut later = installed_cut;
        later.index += 1;
        let mut latency = Latency::new(fixture.directory.path(), Phase::Read);
        let (installed, purged) = latency
            .run(Duration::from_secs(8), async {
                tokio::join!(
                    fixture
                        .machine
                        .install_snapshot(&fixture.meta, fixture.incoming),
                    fixture.log.purge(later),
                )
            })
            .await;
        installed.expect("the unrelated install must finish");
        assert!(
            purged.is_err(),
            "the ordinary application wait stays bounded"
        );
        assert_eq!(
            fixture.machine.applied_state().await.unwrap().0,
            Some(installed_cut)
        );
        assert!(fixture
            .log
            .get_log_state()
            .await
            .unwrap()
            .last_purged_log_id
            .is_none());
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_cancelled_install_releases_its_purge_waiter() {
    watchdog(async {
        use std::future::{poll_fn, Future};
        use std::task::Poll;

        let mut fixture = install_fixture().await;
        let through = fixture.meta.last_log_id.unwrap();
        let incoming_path = fixture.incoming.path().to_path_buf();
        let mut latency = Latency::new(fixture.directory.path(), Phase::Read);
        let mut install = Box::pin(
            fixture
                .machine
                .install_snapshot(&fixture.meta, fixture.incoming),
        );
        let held = tokio::select! {
            step = latency.progress.recv() => step.unwrap(),
            _ = &mut install => panic!("install did not reach verification"),
        };
        let mut purge = Box::pin(fixture.log.purge(through));
        assert!(poll_fn(|cx| Poll::Ready(purge.as_mut().poll(cx)))
            .await
            .is_pending());
        drop(install);
        drop(held);
        drop(latency);
        let purged = tokio::time::timeout(Duration::from_secs(1), purge)
            .await
            .expect("cancellation must release purge without waiting for its 30s timer");
        assert!(
            purged.is_err(),
            "cancelled installation cannot authorize purge"
        );
        assert!(!incoming_path.exists());
        assert!(fixture.machine.applied_state().await.unwrap().0.is_none());
        assert!(fixture
            .log
            .get_log_state()
            .await
            .unwrap()
            .last_purged_log_id
            .is_none());
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_failed_install_releases_its_purge_waiter() {
    watchdog(async {
        let mut fixture = install_fixture().await;
        let through = fixture.meta.last_log_id.unwrap();
        let incoming_path = fixture.incoming.path().to_path_buf();
        let mut latency = Latency::new(fixture.directory.path(), Phase::Read);
        let (installed, purged) = {
            let operation = async {
                tokio::join!(
                    fixture
                        .machine
                        .install_snapshot(&fixture.meta, fixture.incoming),
                    fixture.log.purge(through),
                )
            };
            tokio::pin!(operation);
            let held = tokio::select! {
                step = latency.progress.recv() => step.unwrap(),
                _ = &mut operation => panic!("install did not reach the bounded verification read"),
            };
            tokio::time::pause();
            tokio::time::advance(SNAPSHOT_OPERATION_TIMEOUT + Duration::from_secs(1)).await;
            use std::future::{poll_fn, Future};
            use std::task::Poll;
            let early = poll_fn(|cx| Poll::Ready(operation.as_mut().poll(cx))).await;
            tokio::time::resume();
            drop(held);
            drop(latency);
            match early {
                Poll::Ready(result) => result,
                Poll::Pending => operation.await,
            }
        };
        assert!(installed.is_err(), "a stalled install must fail");
        assert!(
            purged.is_err(),
            "failed installation cannot authorize purge"
        );
        assert!(
            !incoming_path.exists(),
            "failed receiving artifact is removed"
        );
        assert!(fixture.machine.applied_state().await.unwrap().0.is_none());
        assert!(fixture
            .log
            .get_log_state()
            .await
            .unwrap()
            .last_purged_log_id
            .is_none());
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_build_survives_a_large_steadily_read_file() {
    watchdog(async {
        let directory = tempfile::tempdir().unwrap();
        let (_backend, mut machine, _) = machine(directory.path()).await;
        let mut latency = Latency::new(directory.path(), Phase::Envelope);
        let started = tokio::time::Instant::now();
        let result = latency
            .run(Duration::from_secs(8), async {
                machine.get_snapshot_builder().await.build_snapshot().await
            })
            .await;
        drop(latency);
        let snapshot = result.expect("a healthy multi-chunk build must outlive 60 seconds");
        assert!(started.elapsed() > SNAPSHOT_OPERATION_TIMEOUT);
        assert!(
            tokio::fs::metadata(snapshot.snapshot.path())
                .await
                .unwrap()
                .len()
                > PAYLOAD_BYTES
        );
        assert_eq!(snapshot.meta.last_log_id.unwrap().index, 16);
        assert_eq!(
            machine.get_current_snapshot().await.unwrap().unwrap().meta,
            snapshot.meta
        );
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_install_survives_a_large_steadily_read_file() {
    watchdog(async {
        let source_directory = tempfile::tempdir().unwrap();
        let (_source, mut source, identity) = machine(source_directory.path()).await;
        let snapshot = source
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .unwrap();
        let bytes = tokio::fs::read(snapshot.snapshot.path()).await.unwrap();
        assert!(bytes.len() as u64 > PAYLOAD_BYTES);
        let target_directory = tempfile::tempdir().unwrap();
        let target = SqliteBackend::open_with_audit_key(
            target_directory.path().join("config.sqlite"),
            true,
            0,
            AuditKey::new([0x66; 32]).unwrap(),
        )
        .await
        .unwrap();
        let (_, mut target, _) = open(
            &target,
            target_directory.path().join("snapshots"),
            identity,
            BTreeSet::from([ConsensusNodeId::new(1).unwrap()]),
        )
        .await
        .unwrap();
        let mut incoming = target.begin_receiving_snapshot().await.unwrap();
        incoming.write_all(&bytes).await.unwrap();
        let mut latency = Latency::new(target_directory.path(), Phase::Read);
        let started = tokio::time::Instant::now();
        let result = latency
            .run(
                Duration::from_secs(8),
                target.install_snapshot(&snapshot.meta, incoming),
            )
            .await;
        drop(latency);
        result.expect("a healthy multi-chunk install must outlive 60 seconds");
        assert!(started.elapsed() > SNAPSHOT_OPERATION_TIMEOUT);
        let installed = target.get_current_snapshot().await.unwrap().unwrap();
        assert_eq!(installed.meta, snapshot.meta);
        assert_eq!(
            tokio::fs::read(installed.snapshot.path()).await.unwrap(),
            bytes
        );
        assert_eq!(
            target.applied_state().await.unwrap().0,
            snapshot.meta.last_log_id
        );
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_reopen_verifies_the_large_publication_without_a_size_blind_deadline() {
    watchdog(async {
        let directory = tempfile::tempdir().unwrap();
        let (backend, mut source, identity) = machine(directory.path()).await;
        let snapshot = source
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .unwrap();
        let expected = tokio::fs::read(snapshot.snapshot.path()).await.unwrap();
        assert!(expected.len() as u64 > PAYLOAD_BYTES);
        drop(source);
        let mut latency = Latency::new(directory.path(), Phase::Read);
        let started = tokio::time::Instant::now();
        let result = latency
            .run(
                Duration::from_secs(8),
                open(
                    &backend,
                    directory.path().join("snapshots"),
                    identity,
                    BTreeSet::from([ConsensusNodeId::new(1).unwrap()]),
                ),
            )
            .await;
        drop(latency);
        let (_, mut reopened, _) = result.expect("a healthy large snapshot remains restartable");
        assert!(started.elapsed() > SNAPSHOT_OPERATION_TIMEOUT);
        let current = reopened.get_current_snapshot().await.unwrap().unwrap();
        assert_eq!(current.meta, snapshot.meta);
        assert_eq!(
            tokio::fs::read(current.snapshot.path()).await.unwrap(),
            expected
        );
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_sqlite_backup_uses_its_measured_input_size() {
    watchdog(async {
        let directory = tempfile::tempdir().unwrap();
        let (_backend, mut machine, _) = machine(directory.path()).await;
        let pages: u32 = machine
            .core
            .run_sqlite(|conn| {
                conn.query_row("PRAGMA page_count", [], |row| row.get(0))
                    .map_err(|_| sqlite::invalid_data("test snapshot size query failed"))
            })
            .await
            .unwrap();
        let steps = pages.div_ceil(128);
        assert!(steps > 1);
        let mut latency = Latency::new(directory.path(), Phase::Backup);
        let started = tokio::time::Instant::now();
        let snapshot = latency
            .run(Duration::from_secs(62) / steps, async {
                machine.get_snapshot_builder().await.build_snapshot().await
            })
            .await
            .expect("the measured backup allowance covers more than 60 seconds of progress");
        drop(latency);
        assert!(started.elapsed() > SNAPSHOT_OPERATION_TIMEOUT);
        assert_eq!(snapshot.meta.last_log_id.unwrap().index, 16);
        assert_eq!(
            machine.get_current_snapshot().await.unwrap().unwrap().meta,
            snapshot.meta
        );
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_stalled_envelope_is_bounded_and_cleans_staging() {
    watchdog(async {
        let directory = tempfile::tempdir().unwrap();
        let (_backend, machine, _) = machine(directory.path()).await;
        let owner = machine.core.snapshot_directory_owner().unwrap();
        let raw = machine.core.snapshot_dir.join("raw.sqlite");
        let staging = machine.core.snapshot_dir.join("snapshot.part");
        tokio::fs::write(&raw, vec![0x71; 2 * 1024 * 1024])
            .await
            .unwrap();
        let mut latency = Latency::new(directory.path(), Phase::Envelope);
        let operation = envelope_snapshot_database(&raw, &staging, owner);
        tokio::pin!(operation);
        let held = tokio::select! {
            step = latency.progress.recv() => step.unwrap(),
            _ = &mut operation => panic!("expected the first bounded file read"),
        };
        tokio::time::pause();
        tokio::time::advance(SNAPSHOT_OPERATION_TIMEOUT + Duration::from_secs(1)).await;
        let error = match operation.await {
            Err(error) => error,
            Ok(_) => panic!("stalled read succeeded"),
        };
        tokio::time::resume();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(!staging.exists());
        assert!(raw.exists());
        drop(held);
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_stalled_backup_keeps_the_previous_publication() {
    watchdog(async {
        let directory = tempfile::tempdir().unwrap();
        let (_backend, mut machine, _) = machine(directory.path()).await;
        let previous = machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .unwrap();
        let bytes: u64 = machine
            .core
            .run_sqlite(|conn| {
                let pages: u64 = conn
                    .query_row("PRAGMA page_count", [], |row| row.get(0))
                    .map_err(|_| sqlite::invalid_data("test snapshot size query failed"))?;
                let size: u64 = conn
                    .query_row("PRAGMA page_size", [], |row| row.get(0))
                    .map_err(|_| sqlite::invalid_data("test snapshot size query failed"))?;
                Ok(pages * size)
            })
            .await
            .unwrap();
        let mut latency = Latency::new(directory.path(), Phase::Backup);
        let mut builder = machine.get_snapshot_builder().await;
        let operation = builder.build_snapshot();
        tokio::pin!(operation);
        let held = tokio::select! {
            step = latency.progress.recv() => step.unwrap(),
            _ = &mut operation => panic!("expected the first backup step"),
        };
        tokio::time::pause();
        tokio::time::advance(
            SNAPSHOT_OPERATION_TIMEOUT + Duration::from_secs(bytes.div_ceil(1024 * 1024) + 2),
        )
        .await;
        // Poll the elapsed timer before releasing the worker: cancellation
        // must win before it can authorize any publication.
        use std::future::{poll_fn, Future};
        use std::task::Poll;
        assert!(poll_fn(|cx| Poll::Ready(operation.as_mut().poll(cx)))
            .await
            .is_pending());
        tokio::time::resume();
        held.send(()).unwrap();
        drop(latency);
        assert!(operation.await.is_err());
        assert_eq!(
            machine.get_current_snapshot().await.unwrap().unwrap().meta,
            previous.meta
        );
        let mut entries = tokio::fs::read_dir(directory.path().join("snapshots"))
            .await
            .unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            assert!(!entry.file_name().to_string_lossy().starts_with("build-"));
        }
    })
    .await;
}

#[tokio::test]
async fn snapshot_progress_writes_invalidate_the_descriptors_verified_digest() {
    let directory = tempfile::tempdir().unwrap();
    let (_backend, machine, _) = machine(directory.path()).await;
    let owner = machine.core.snapshot_directory_owner().unwrap();
    let raw = machine.core.snapshot_dir.join("raw.sqlite");
    let enveloped = machine.core.snapshot_dir.join("snapshot.opc");
    tokio::fs::write(&raw, vec![0x72; 2 * 1024 * 1024])
        .await
        .unwrap();
    let (_, _, _cleanup) = envelope_snapshot_database(&raw, &enveloped, owner.clone())
        .await
        .unwrap();
    let mut received = ConfigSnapshotFile::create_owned(
        machine.core.snapshot_dir.join("received.part"),
        owner.clone(),
    )
    .await
    .unwrap();
    received
        .write_all(&tokio::fs::read(&enveloped).await.unwrap())
        .await
        .unwrap();
    let verified = verify_open_snapshot_envelope(&mut received, owner.clone())
        .await
        .unwrap();
    assert_eq!(received.verified_envelope().unwrap().checksum, verified.1);
    received.seek(io::SeekFrom::Start(0)).await.unwrap();
    received.write_all(&[0x73]).await.unwrap();
    assert!(received.verified_envelope().is_none());
    assert!(verify_open_snapshot_envelope(&mut received, owner.clone())
        .await
        .is_err());
    assert!(received.verified_envelope().is_none());
}

#[tokio::test]
async fn snapshot_progress_received_sync_rejects_invalid_lengths_before_io() {
    watchdog(async {
        for bytes in [0, SNAPSHOT_FOOTER_BYTES, SNAPSHOT_MAX_ENVELOPE_BYTES + 1] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("incoming.snapshot");
            let mut incoming = ConfigSnapshotFile::create(path.clone()).await.unwrap();
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(bytes)
                .unwrap();
            let mut latency = Latency::new(directory.path(), Phase::Sync);
            let result = sync_received_snapshot(&mut incoming).await;
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert!(
                matches!(
                    latency.progress.try_recv(),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                ),
                "an invalid length must be rejected before whole-file synchronization"
            );
        }
    })
    .await;
}
