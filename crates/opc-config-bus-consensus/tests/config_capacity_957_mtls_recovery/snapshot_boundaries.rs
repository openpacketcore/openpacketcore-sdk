//! Real mTLS decoder and snapshot staging extent boundaries.
//! Sparse staging checks preserve the production 64 GiB body plus 50-byte footer
//! ceiling; they are not a valid 64 GiB SQLite snapshot or physical-space proof.

use super::*;
use std::os::unix::fs::MetadataExt;

const CHUNK_BYTES: usize = 1_048_576;
const SNAPSHOT_ID_BYTES: usize = 128;
const SNAPSHOT_WIRE_BYTES: u64 = 68_719_476_736 + 50;

#[derive(Clone, Copy)]
enum Case {
    Fields,
    Extent,
    Overflow,
}

fn encode_chunk(
    profile: ConfigCapacityProfile,
    vote: Vote<ConsensusNodeId>,
    id: String,
    offset: u64,
    data: Vec<u8>,
) -> Vec<u8> {
    let revision = match profile {
        ConfigCapacityProfile::Legacy => 7,
        ConfigCapacityProfile::BoundedV1 => 8,
        _ => panic!("unsupported fixture profile"),
    };
    encode(
        revision,
        FirstSnapshotChunk {
            vote,
            meta: SnapshotMeta {
                last_log_id: None,
                last_membership: StoredMembership::default(),
                snapshot_id: id,
            },
            offset,
            data,
            done: false,
        },
    )
}

async fn send(
    peer: &RemoteSessionConsensusPeer,
    identity: ConsensusIdentity,
    sender: ConsensusNodeId,
    payload: Vec<u8>,
) -> ConsensusWireResponse {
    peer.call_with_timeout(
        ConsensusWireRequest::try_new(
            identity,
            sender,
            ConsensusRpcFamily::InstallSnapshot,
            payload,
        )
        .expect("bounded outer snapshot request"),
        DURABLE_CONSENSUS_OPERATION_TIMEOUT,
    )
    .await
    .expect("actual authenticated snapshot service response")
}

fn accepted_for_profile(profile: ConfigCapacityProfile, response: ConsensusWireResponse) {
    let reply = response
        .result
        .expect("matching snapshot reaches native engine");
    let expected = match profile {
        ConfigCapacityProfile::Legacy => [7, 0],
        ConfigCapacityProfile::BoundedV1 => [8, 0],
        _ => panic!("unsupported fixture profile"),
    };
    assert!(
        reply.starts_with(&expected),
        "native snapshot reply is a matching-profile Ok"
    );
}

fn file_metadata(directory: &Path) -> BTreeMap<PathBuf, (u64, u64, u64, i64, i64)> {
    std::fs::read_dir(directory)
        .expect("native staging directory")
        .map(|entry| {
            let entry = entry.expect("staging entry");
            let metadata = entry.metadata().expect("staging metadata");
            assert!(
                metadata.is_file(),
                "only native staging files in this fixture"
            );
            (
                PathBuf::from(entry.file_name()),
                (
                    metadata.ino(),
                    metadata.len(),
                    metadata.blocks(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                ),
            )
        })
        .collect()
}

async fn run(case: Case, profile: ConfigCapacityProfile) {
    let chunk = |vote, id, offset, data| encode_chunk(profile, vote, id, offset, data);
    let accepted = |response| accepted_for_profile(profile, response);
    let directory = disk_fixture();
    let pki = Pki::new();
    let manifest = manifest();
    let addresses = [0, 1, 2].map(|_| Arc::new(RwLock::new(None)));
    let faults = [0, 1, 2].map(|_| Arc::new(Fault::default()));
    let databases = [0, 1, 2].map(|index| directory.join(format!("config-{index}.sqlite")));
    let stores = open_members(
        &directory, &manifest, &pki, &addresses, &faults, false, profile,
    )
    .await;
    let (servers, released) = snapshot::listen(&stores, &pki, &manifest, &addresses).await;
    snapshot::ready(&stores).await;
    let leader_id = stores[0]
        .status()
        .leader_id
        .expect("native boundary leader");
    let leader = stores
        .iter()
        .position(|store| store.status().node_id == leader_id)
        .expect("leader belongs to manifest");
    let target = (leader + 1) % 3;
    let (input, aad, plaintext) = commit(&stores[leader], 1, None).await;
    let expected = input.record().clone();
    let prepared = stores[leader]
        .prepare_recoverable_commit(
            ConfigConsensusRequestId::from_bytes([0xC7; 16]),
            input,
            CALLER,
        )
        .expect("at-limit boundary control preparation");
    let handle_bytes = prepared.recovery_handle().as_bytes().to_vec();
    stores[leader]
        .append_prepared_commit_local(prepared)
        .await
        .expect("real native at-limit control");
    for store in &stores {
        let record = store
            .load_latest()
            .await
            .expect("applied control barrier")
            .expect("control record");
        assert!(record.record == expected, "exact control readback");
        assert_decrypted(&record.record, &aad, &plaintext);
        let status = store.status();
        assert_eq!(
            status.applied_index, status.committed_index,
            "successful control applied before refusal baseline"
        );
    }
    let peer = RemoteSessionConsensusPeer::new_profiled_with_resolver(
        manifest
            .bind_local(replica_id(leader))
            .expect("real sender")
            .bind_remote(replica_id(target))
            .expect("real receiver"),
        resolver(addresses[target].clone()),
        pki.client(leader),
    );
    let identity = manifest.consensus_identity();
    let current_vote = Vote::new_committed(stores[leader].status().term, leader_id);
    match case {
        Case::Fields => {
            // Stale votes reach the native engine after complete decoding without
            // creating a transfer. Real contiguous transfers have separate tests.
            let stale_vote = Vote::new(0, leader_id);
            for id in [
                "x".repeat(SNAPSHOT_ID_BYTES),
                "é".repeat(SNAPSHOT_ID_BYTES / 2),
            ] {
                assert_eq!(id.len(), SNAPSHOT_ID_BYTES);
                let before = authority_state(&directory, &databases).await;
                accepted(
                    send(
                        &peer,
                        identity,
                        leader_id,
                        chunk(stale_vote, id, 0, vec![0xA6; CHUNK_BYTES]),
                    )
                    .await,
                );
                let after = authority_state(&directory, &databases).await;
                assert!(
                    before == after,
                    "at-limit stale-vote control preserves complete authority and staging"
                );
            }
            let invalid = [
                (
                    "chunk",
                    chunk(
                        current_vote,
                        "synthetic-boundary".into(),
                        0,
                        vec![0xA6; CHUNK_BYTES + 1],
                    ),
                ),
                (
                    "ascii_id",
                    chunk(
                        current_vote,
                        "x".repeat(SNAPSHOT_ID_BYTES + 1),
                        0,
                        vec![0xA6; CHUNK_BYTES],
                    ),
                ),
                (
                    "utf8_id",
                    chunk(
                        current_vote,
                        format!("{}x", "é".repeat(SNAPSHOT_ID_BYTES / 2)),
                        0,
                        vec![0xA6; CHUNK_BYTES],
                    ),
                ),
            ];
            for (boundary, payload) in invalid {
                let before = authority_state(&directory, &databases).await;
                let response = send(&peer, identity, leader_id, payload).await;
                assert!(matches!(response.result, Err(ConsensusPeerError::Protocol)),
                    "CONFIG_CAPACITY_SNAPSHOT_FIELD_RED: one-over field rejected before native handoff ({boundary})");
                let after = authority_state(&directory, &databases).await;
                assert!(
                    before == after,
                    "field refusal preserves complete authority and snapshot contents"
                );
            }
            println!("CONFIG_CAPACITY_SNAPSHOT_FIELDS chunk_bytes=1048576 id_bytes=128 at_limit=2 one_over=3 mtls=true native_wal=true authority_unchanged=true");
        }
        Case::Extent | Case::Overflow => {
            let id = "synthetic-staging-extent".to_owned();
            accepted(
                send(
                    &peer,
                    identity,
                    leader_id,
                    chunk(current_vote, id.clone(), 0, vec![0xA1]),
                )
                .await,
            );
            if matches!(case, Case::Extent) {
                accepted(
                    send(
                        &peer,
                        identity,
                        leader_id,
                        chunk(
                            current_vote,
                            id.clone(),
                            SNAPSHOT_WIRE_BYTES - 1,
                            vec![0xB2],
                        ),
                    )
                    .await,
                );
            }
            // The production receiver seeks on an offset change. A zero-byte
            // seek to zero awaits the preceding tokio file write before observing
            // it; no sleep, direct file mutation or deadline change is needed.
            accepted(
                send(
                    &peer,
                    identity,
                    leader_id,
                    chunk(current_vote, id.clone(), 0, Vec::new()),
                )
                .await,
            );
            let snapshots = directory.join(format!("snapshots-{target}"));
            let before_files = file_metadata(&snapshots);
            assert_eq!(before_files.len(), 1, "one active incoming native file");
            let (_, extent, blocks, _, _) = *before_files.values().next().expect("incoming file");
            assert_eq!(
                extent,
                if matches!(case, Case::Extent) {
                    SNAPSHOT_WIRE_BYTES
                } else {
                    1
                }
            );
            assert!(
                blocks * 512 <= 2 * 1024 * 1024,
                "boundary geometry is sparse and uses bounded physical storage"
            );
            let before = databases
                .each_ref()
                .map(|database| authority_digest(database));
            let offset = if matches!(case, Case::Extent) {
                SNAPSHOT_WIRE_BYTES
            } else {
                u64::MAX
            };
            let response = send(
                &peer,
                identity,
                leader_id,
                chunk(current_vote, id, offset, vec![0xC3]),
            )
            .await;
            assert!(matches!(response.result, Err(ConsensusPeerError::Protocol)),
                "CONFIG_CAPACITY_SNAPSHOT_EXTENT_RED: one-over or overflowing extent rejected before native seek/write");
            assert!(
                before
                    == databases
                        .each_ref()
                        .map(|database| authority_digest(database)),
                "extent refusal preserves complete native authority"
            );
            assert!(before_files == file_metadata(&snapshots),
                "extent refusal preserves incoming file identity, length, blocks and modification time");
            println!("CONFIG_CAPACITY_SNAPSHOT_EXTENT max_wire_bytes={SNAPSHOT_WIRE_BYTES} overflow={} mtls=true native_wal=true pre_write=true sparse_geometry_only=true", matches!(case, Case::Overflow));
        }
    }
    let handle =
        ConfigCommitRecoveryHandle::from_bytes(&handle_bytes).expect("only original handle");
    for store in &stores {
        assert!(
            matches!(
                store
                    .lookup_commit_operation(&handle, CALLER)
                    .await
                    .expect("read-only original recovery"),
                ConfigCommitRecoveryOutcome::Committed
            ),
            "known original commit remains committed"
        );
        let record = store
            .load_latest()
            .await
            .expect("post-refusal quorum read")
            .expect("retained original record");
        assert!(record.record == expected, "refusal preserves exact record");
        assert_decrypted(&record.record, &aad, &plaintext);
    }
    snapshot::stop(stores, servers, released, &addresses).await;
}

native_case!(config_capacity_957_snapshot_field_limits_over_real_mtls, {
    run(Case::Fields, ConfigCapacityProfile::BoundedV1).await;
});

native_case!(
    config_capacity_957_snapshot_one_over_extent_before_native_write,
    {
        run(Case::Extent, ConfigCapacityProfile::BoundedV1).await;
    }
);

native_case!(
    config_capacity_957_snapshot_overflow_extent_before_native_seek,
    {
        run(Case::Overflow, ConfigCapacityProfile::BoundedV1).await;
    }
);

native_case!(
    config_capacity_957_legacy_snapshot_one_over_extent_before_native_write,
    {
        run(Case::Extent, ConfigCapacityProfile::Legacy).await;
    }
);

native_case!(
    config_capacity_957_legacy_snapshot_overflow_extent_before_native_seek,
    {
        run(Case::Overflow, ConfigCapacityProfile::Legacy).await;
    }
);
