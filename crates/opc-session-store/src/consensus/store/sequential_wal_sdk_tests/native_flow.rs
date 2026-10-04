//! One SDK witness for the selected native owner, including live reads,
//! unanimous V2 activation, strict snapshots, and an orderly cold reopen.

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_public_v2_reads_two_strict_snapshots_and_reopen() {
    let root = std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").expect("strict root required");
    let mut snapshots = tempfile::tempdir_in(root).expect("strict native snapshot root");
    snapshots.disable_cleanup(true);
    let mut fleet = Fleet::new_native("native_flow");
    fleet.directory.disable_cleanup(true);
    fleet.snapshot_root = Some(snapshots.path().to_path_buf());
    eprintln!(
        "native_sdk_paths={}",
        serde_json::json!({"mutable":fleet.directory.path(),"snapshots":snapshots.path()})
    );
    fleet.open().await;
    let provider = provider();
    let result = AssertUnwindSafe(async {
        let ingress = fleet
            .stores
            .iter()
            .position(|store| store.status().leader_id == Some(store.status().node_id))
            .expect("native leader");
        let epoch = FencedTransitionV2HistoryEpoch::new(1).unwrap();
        let mut retained = Vec::new();
        for round in 0..2 {
            let mut requests = Vec::new();
            for index in round * 8..(round + 1) * 8 {
                let observation = fleet.stores[ingress]
                    .observe_fenced_transition(&key(100 + index))
                    .await
                    .expect("native public observation");
                requests.push(
                    v2_create_request(index, epoch, observation.current_fence(), &provider).await,
                );
            }
            let outcomes = fleet.stores[ingress]
                .fenced_transition_v2_batch(requests.clone())
                .await
                .expect("native public V2 batch");
            for (request, outcome) in requests.into_iter().zip(outcomes) {
                let outcome = outcome.expect("native exact V2 effect");
                assert_v2_create(&request, &outcome);
                retained.push((request, outcome));
            }
            verify(&fleet, &provider, &retained).await;
            for store in &fleet.stores {
                let before = store.status().completed_snapshot_count;
                store
                    .inner
                    .raft
                    .trigger()
                    .snapshot()
                    .await
                    .expect("normal native snapshot trigger");
                tokio::time::timeout(Duration::from_secs(30), async {
                    while store.status().completed_snapshot_count == before {
                        let metrics = store.inner.raft.metrics().borrow().clone();
                        assert!(
                            metrics.running_state.is_ok(),
                            "native snapshot must not stop Raft: {metrics:?}"
                        );
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("strict native snapshot completed");
                let wal = store.inner.private_wal.as_ref().unwrap();
                let current = wal
                    .with_native_read(|state| Ok(state.current_snapshot()))
                    .unwrap()
                    .expect("native selected snapshot");
                assert!(current.0.snapshot_id.starts_with("native-"));
                assert_eq!(
                    wal.native_sql_fallback_count().unwrap(),
                    0,
                    "live SQL helper was never selected"
                );
            }
        }
        fleet.observe_costs("native_two_strict_snapshots_verified");
        retained
    })
    .catch_unwind()
    .await;
    let closed = fleet.close().await;
    let retained = result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    for (voter, wal) in closed.iter().enumerate() {
        wal.native_audit_closed(
            |current,origin| admit_native_snapshots(&snapshots.path().join(format!("snapshots-{voter}")), current,origin),
            AdmittedNativeSnapshots::install_source,
            AdmittedNativeSnapshots::verify,
            |state| {
                assert_eq!(state.receipt_count(), retained.len());
                for (request, outcome) in &retained {
                    assert!(matches!(state.status(request).expect("cold native exact receipt"), FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(outcome.clone())));
                }
                Ok(())
            },
        ).expect("read-only native recovery and strict snapshot audit");
    }
    fleet.open().await;
    let result = AssertUnwindSafe(async {
        verify(&fleet, &provider, &retained).await;
        for store in &fleet.stores {
            let wal = store.inner.private_wal.as_ref().unwrap();
            assert_eq!(
                wal.native_sql_fallback_count().unwrap(),
                0,
                "reopened live SQL helper was never selected"
            );
            assert_eq!(
                wal.with_native_read(|state| Ok(state.receipt_count()))
                    .unwrap(),
                16
            );
        }
        fleet.observe_costs("native_reopen_all_exact_receipts_verified");
    })
    .catch_unwind()
    .await;
    fleet.close().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

pub(super) struct AdmittedNativeSnapshots {
    pins: Vec<(
        crate::consensus::snapshot::PinnedSqliteFile,
        std::path::PathBuf,
        u64,
    )>,
    installation: Option<(
        crate::sqlite::consensus::wal::snapshot::InstallSource,
        tempfile::TempDir,
    )>,
}

impl AdmittedNativeSnapshots {
    pub(super) fn install_source(
        &self,
    ) -> Option<&crate::sqlite::consensus::wal::snapshot::InstallSource> {
        self.installation.as_ref().map(|(source, _)| source)
    }

    pub(super) fn verify(&self) -> std::io::Result<()> {
        for (pin, path, length) in &self.pins {
            pin.verify_bound_immutable_snapshot_envelope(path, *length)?;
        }
        if let Some((source, _)) = &self.installation {
            source.verify()?;
        }
        Ok(())
    }
}

pub(super) fn admit_native_snapshots(
    directory: &std::path::Path,
    current: Vec<crate::sqlite::consensus::CurrentSnapshot>,
    origin: Option<crate::sqlite::consensus::CurrentSnapshot>,
) -> std::io::Result<AdmittedNativeSnapshots> {
    use crate::consensus::snapshot::{
        readonly_nofollow, PinnedSqliteFile, SNAPSHOT_ENVELOPE_FOOTER_BYTES, SNAPSHOT_MAX_BYTES,
    };
    use std::io::Write;
    use std::os::unix::fs::FileExt;
    let mut admitted = AdmittedNativeSnapshots {
        pins: Vec::new(),
        installation: None,
    };
    for candidate in current {
        let (_, name, checksum, length) = &candidate;
        let path = directory.join(name);
        let mut pinned = PinnedSqliteFile::from_file_and_verify(
            readonly_nofollow(&path)?,
            path.clone(),
            SnapshotIntegrityPolicy::FsVerity,
        )?;
        pinned.verify_snapshot_envelope_and_bind_immutable_generation(
            &path,
            b"OPCSNP01",
            SNAPSHOT_ENVELOPE_FOOTER_BYTES,
            SNAPSHOT_MAX_BYTES,
            *checksum,
            *length,
        )?;
        pinned.verify_bound_immutable_snapshot_envelope(&path, *length)?;
        if origin.as_ref() == Some(&candidate) {
            // The same original incoming payload is reconstructed from its
            // strict published descriptor. Its sole derivative lives outside
            // the durable snapshot/WAL namespaces and owns its cleanup.
            let scratch =
                tempfile::tempdir_in(directory.parent().ok_or_else(|| {
                    std::io::Error::other("native audit snapshot parent missing")
                })?)?;
            let raw_path = scratch.path().join("incoming.sqlite");
            let mut raw = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&raw_path)?;
            let payload = length
                .checked_sub(SNAPSHOT_ENVELOPE_FOOTER_BYTES)
                .ok_or_else(|| std::io::Error::other("native audit payload extent invalid"))?;
            let _memory =
                crate::consensus::verified_snapshot::VerificationMemory::reserve(64 * 1024)?;
            let mut bytes = zeroize::Zeroizing::new(vec![0; 64 * 1024]);
            let mut offset = 0;
            while offset < payload {
                let count = (payload - offset).min(bytes.len() as u64) as usize;
                pinned.file().read_exact_at(&mut bytes[..count], offset)?;
                raw.write_all(&bytes[..count])?;
                offset += count as u64;
            }
            raw.sync_all()?;
            drop(raw);
            pinned.verify_bound_immutable_snapshot_envelope(&path, *length)?;
            let mut raw = PinnedSqliteFile::from_file(readonly_nofollow(&raw_path)?, raw_path)?;
            raw.seal_fixed()?;
            let source = crate::sqlite::consensus::wal::snapshot::InstallSource::new_native(
                &candidate.0,
                name,
                *checksum,
                *length,
                raw,
                pinned.try_clone()?,
                &path,
            )?;
            admitted.installation = Some((source, scratch));
        }
        admitted.pins.push((pinned, path, *length));
    }
    if origin.is_some() && admitted.installation.is_none() {
        return Err(std::io::Error::other(
            "native audit original source is not retained",
        ));
    }
    admitted.verify()?;
    Ok(admitted)
}

async fn verify(
    fleet: &Fleet,
    provider: &Arc<MemoryKeyProvider>,
    retained: &[(FencedTransitionV2Request, FencedTransitionOutcome)],
) {
    for store in &fleet.stores {
        let encrypted = EncryptingSessionBackend::new(
            Arc::new(store.clone()),
            provider.clone(),
            "private-wal-sdk",
        );
        for (request, outcome) in retained {
            assert!(
                matches!(store.fenced_transition_v2_status(request).await.expect("native exact public receipt"),FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(outcome.clone()))
            );
            let FencedTransitionMutation::Create { record } = request.mutation() else {
                panic!("native create fixture");
            };
            let mut expected = record.as_ref().clone();
            expected.payload =
                EncryptedSessionPayload::new(b"private WAL real SDK V2 plaintext round trip");
            assert_eq!(
                encrypted
                    .get(&record.key)
                    .await
                    .expect("native encrypted public read"),
                Some(expected)
            );
        }
        assert_eq!(
            store
                .inner
                .private_wal
                .as_ref()
                .unwrap()
                .native_sql_fallback_count()
                .unwrap(),
            0,
            "live SQL fallback count"
        );
    }
}
