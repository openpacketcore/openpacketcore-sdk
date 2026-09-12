//! One historical voter image per process, including original snapshot installation.
//! This is cold reconstruction and allocation evidence, not a live pod sizing
//! or public operation benchmark. The topology still contains all three voters.

use super::*;
use crate::consensus::SessionTopologyMemberBinding;
use crate::{
    derive_fixed_durable_quorum_consensus_identity, PlacementResiliencePolicy,
    QuorumReplicaDescriptor, QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint,
    ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, ValidatedQuorumTopology,
};
use allocation_counter::measure;
use opc_consensus::{ConsensusClusterId, ConsensusConfigurationEpoch};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::MetadataExt;

fn original_topology() -> ValidatedQuorumTopology {
    // Independently reconstruct the original qualification descriptors;
    // neither membership nor its identity is learned from the input SQL.
    let descriptors = (0..3)
        .map(|index| {
            QuorumReplicaDescriptor::new(
                ReplicaId::new(format!("sdk-702-qualification-voter-{index}")).unwrap(),
                ReplicaEndpoint::new(format!("sdk-702-qualification-voter-{index}.invalid"), 7443)
                    .unwrap(),
                ReplicaTlsIdentity::new(format!(
                    "spiffe://test/session/sdk-702-qualification/{index}"
                ))
                .unwrap(),
                ReplicaFailureDomain::new(format!("sdk-702-qualification-zone-{index}")).unwrap(),
                ReplicaBackingIdentity::new(format!("sdk-702-qualification-disk-{index}")).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let placement = PlacementResiliencePolicy::default();
    let identity = derive_fixed_durable_quorum_consensus_identity(
        ConsensusClusterId::new("sdk-702-v2-qualification").unwrap(),
        ConsensusConfigurationEpoch::new(1).unwrap(),
        &descriptors
            .iter()
            .map(QuorumReplicaDescriptor::configuration_fingerprint)
            .collect::<Vec<_>>(),
        placement,
    );
    ValidatedQuorumTopology::try_from_fixed_durable_quorum_with_placement_policy(
        QuorumTopologyConfig::new_consensus(
            ReplicaId::new("sdk-702-qualification-voter-0").unwrap(),
            descriptors,
            identity,
        ),
        placement,
    )
    .unwrap()
}

fn bindings(
    topology: &ValidatedQuorumTopology,
) -> BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding> {
    topology
        .members()
        .iter()
        .map(|descriptor| {
            let mut endpoint = Sha256::new();
            endpoint.update(b"openpacketcore/session-store/topology-endpoint-binding/v1\0");
            endpoint.update(Sha256::digest(descriptor.endpoint().host().as_bytes()));
            endpoint.update(descriptor.endpoint().port().to_be_bytes());
            let mut tls = Sha256::new();
            tls.update(b"openpacketcore/session-store/topology-tls-binding/v1\0");
            tls.update(Sha256::digest(
                descriptor.tls_identity().as_str().as_bytes(),
            ));
            let mut backing = Sha256::new();
            backing.update(b"openpacketcore/session-store/topology-backing-binding/v1\0");
            backing.update(descriptor.backing_identity().fingerprint());
            (
                topology.consensus_node_id(descriptor.replica_id()).unwrap(),
                SessionTopologyMemberBinding::new(
                    descriptor.configuration_fingerprint(),
                    endpoint.finalize().into(),
                    tls.finalize().into(),
                    backing.finalize().into(),
                ),
            )
        })
        .collect()
}

fn observation(stage: &str, voter: usize) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let smaps = std::fs::read_to_string("/proc/self/smaps_rollup").unwrap();
    let kib = |text: &str, key: &str| -> u64 {
        let value = text
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .unwrap();
        let fields = value.split_whitespace().collect::<Vec<_>>();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[1], "kB");
        fields[0].parse().unwrap()
    };
    eprintln!(
        "isolated_voter_stage={}",
        serde_json::json!({
            "stage": stage, "voter": voter, "pid": std::process::id(),
            "voter_instances": 1, "live_replica_runtime": false,
            "smaps_rss_kib": kib(&smaps, "Rss:"),
            "smaps_pss_kib": kib(&smaps, "Pss:"),
            "vmhwm_estimate_kib": kib(&status, "VmHWM:"),
            "deployment_memory_qualified": false,
        })
    );
}

#[test]
#[ignore = "requires sealed historical fixtures; run each voter in a fresh test process"]
fn one_voter_cold_image_memory_in_a_fresh_process() {
    assert!(std::env::var_os("LD_PRELOAD").is_none());
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::env::var_os("OPC_NATIVE_RETAINED_SNAPSHOT_MANIFEST").unwrap()).unwrap(),
    )
    .unwrap();
    let output = std::path::PathBuf::from(std::env::var_os("OPC_NATIVE_RETAINED_OUTPUT").unwrap());
    std::fs::create_dir(&output).unwrap();
    let inputs = manifest["snapshots"].as_array().unwrap();
    assert_eq!(inputs.len(), 3);
    let topology = original_topology();
    let scope = topology.consensus_identity().unwrap();
    let bindings = bindings(&topology);
    let members = bindings.keys().copied().collect::<BTreeSet<_>>();
    let maximum = crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES;
    let voter: usize = std::env::var("OPC_NATIVE_RETAINED_VOTER")
        .unwrap()
        .parse()
        .unwrap();
    let input = inputs.get(voter).unwrap();
    observation("baseline", voter);
    {
        let source = std::fs::File::open(input["path"].as_str().unwrap()).unwrap();
        let before = source.metadata().unwrap();
        assert!(before.is_file());
        assert_eq!(before.dev(), input["device"].as_u64().unwrap());
        assert_eq!(before.ino(), input["inode"].as_u64().unwrap());
        assert_eq!(before.len(), input["bytes"].as_u64().unwrap());
        // The controller independently measures the existing fs-verity
        // seal before and after this command. Pin this exact descriptor
        // through all SQL validation and both generation-writing passes.
        let mut installed = None;
        let installation = measure(|| {
            installed = Some(
                crate::sqlite::consensus::historical_snapshot_fixture::original_install(
                    std::path::Path::new(input["path"].as_str().unwrap()),
                    source.try_clone().unwrap(),
                    &std::path::PathBuf::from(
                        std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT").unwrap(),
                    )
                    .join(format!("historical-input-cache-{voter}.sqlite")),
                    &output.join(format!("voter-{voter}.installed.sqlite")),
                    scope,
                    &bindings,
                ),
            );
        });
        let installed = installed.unwrap();
        observation("original_install_complete", voter);
        eprintln!(
            "historical_native_original_install voter={voter} live={} peak={} allocations={}",
            installation.bytes_current, installation.bytes_max, installation.count_current
        );
        let mut conn = installed.connection.blocking_lock();
        let path = output.join(format!("voter-{voter}.native"));
        let mut file = std::fs::File::create_new(&path).unwrap();
        let mut identity = None;
        let preparation = measure(|| {
            let prepared = generation::SqlitePreparedBase::prepare_with_origin(
                &mut conn,
                scope,
                &members,
                &bindings,
                PlacementResiliencePolicy::default(),
                None,
                Some(Arc::clone(&installed.origin)),
                installed.binding,
                1,
                1,
                1,
                [0xE8; 32],
                64 * 1024,
                maximum,
                &|| Ok(()),
            )
            .unwrap();
            let mut writer = std::io::BufWriter::new(&mut file);
            identity = Some(prepared.write_to(&mut writer, &|| Ok(())).unwrap());
            writer.flush().unwrap();
        });
        file.sync_all().unwrap();
        drop(file);
        drop(conn);
        let after = source.metadata().unwrap();
        assert_eq!(
            (
                before.dev(),
                before.ino(),
                before.len(),
                before.mtime(),
                before.ctime()
            ),
            (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime(),
                after.ctime()
            )
        );
        drop(source);
        eprintln!(
            "historical_native_preparation voter={voter} live={} peak={} allocations={}",
            preparation.bytes_current, preparation.bytes_max, preparation.count_current
        );
        observation("generation_written", voter);
        let identity = identity.unwrap();
        std::fs::write(
            path.with_extension("identity.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "binding": identity.binding,
                "file_epoch": identity.file_epoch,
                "checkpoint_epoch": identity.checkpoint_epoch,
                "operation_sequence": identity.operation_sequence,
                "frontiers": identity.frontiers,
                "length": identity.length,
                "block_bytes": identity.block_bytes,
                "digest": identity.digest,
            }))
            .unwrap(),
        )
        .unwrap();
        let mut admitted = None;
        let admission = measure(|| {
            admitted = Some(
                generation::Catalog::open_with_origin(
                    &path,
                    identity,
                    maximum,
                    generation::CatalogScope {
                        identity: scope,
                        members: &members,
                        roster_root: None,
                    },
                    Some(Arc::clone(&installed.origin)),
                    [0xE8; 32],
                    &|| Ok(()),
                )
                .unwrap(),
            );
        });
        let (owner, catalog) = admitted.unwrap();
        observation("catalog_admitted", voter);
        drop(installed);
        let mut cold = None;
        let conversion = measure(|| {
            cold = Some(catalog.into_storage(&|| Ok(())).unwrap());
            drop(owner);
        });
        let cold = cold.unwrap();
        cold.validate_image().unwrap();
        assert_eq!(cold.business.keys.len(), 50_000);
        assert_eq!(
            cold.business.receipts.len() as u64,
            input["counts"]["consensus_fenced_transition_v2_receipts"]
                .as_u64()
                .unwrap()
        );
        assert_eq!(
            cold.business.notifications.len(),
            cold.business.receipts.len()
        );
        assert_eq!(
            cold.business.generic_receipts.len() as u64,
            input["counts"]["consensus_request_outcomes"]
                .as_u64()
                .unwrap()
        );
        assert_eq!(
            cold.log.entries.len() as u64,
            input["counts"]["consensus_log"].as_u64().unwrap()
        );
        assert!(cold
            .business
            .receipts
            .values()
            .all(|row| row.cold.is_some()));
        eprintln!(
            "historical_native_admitted voter={voter} receipts={} admission_live={} admission_peak={} conversion_net={} conversion_peak={}",
            cold.business.receipts.len(), admission.bytes_current, admission.bytes_max,
            conversion.bytes_current, conversion.bytes_max
        );
        observation("cold_image_retained", voter);
        let mut roots = Vec::new();
        let counts = cold.release_roots_for_test(|root, release| {
            let measured = measure(release);
            roots.push(serde_json::json!({
                "root": root,
                "released_bytes": i128::from(measured.bytes_total) - i128::from(measured.bytes_current),
                "released_allocations": i128::from(measured.count_total) - i128::from(measured.count_current),
            }));
        });
        eprintln!(
            "isolated_voter_owners={}",
            serde_json::json!({
                "voter": voter, "counts": counts, "roots": roots,
                "scope": "one_cold_native_image_after_complete_original_snapshot_install",
                "live_replica_runtime": false, "deployment_memory_qualified": false,
            })
        );
        observation("native_roots_released", voter);
    }
}
