//! Native fixtures for private-capability binding and original refusal order.
//! The separate cost cases prove actual committed readback and retained reopen.

use super::*;
use crate::backend::SqliteBackend;
use crate::consensus::store::config_capacity_cost_observation::Observation;
use crate::consensus::store::{ForwardMutationReply, ReadBarrierReply};
use crate::types::ConfigStore;
use crate::{AuditKey, RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

async fn store(profile: ConfigCapacityProfile) -> ConsensusConfigStore {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit disk scratch root");
    let root = tempfile::Builder::new()
        .prefix("config-admission-")
        .tempdir_in(scratch)
        .expect("private native fixture")
        .keep();
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&root)
        .output()
        .expect("filesystem detector");
    assert!(filesystem.status.success());
    let filesystem = std::str::from_utf8(&filesystem.stdout)
        .expect("filesystem name")
        .trim();
    assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));
    let node = opc_consensus::ConsensusNodeId::new(1).unwrap();
    let identity = opc_consensus::ConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::from_bytes([0x71; 32]),
        opc_consensus::ConsensusConfigurationId::from_bytes([0x72; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let topology = crate::ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node]))
        .expect("synthetic immutable scope");
    let options = RetainedConfigOptions::new(
        root.join("config.sqlite"),
        RetainedConfigBinding::new(topology.clone(), [0x73; 32], [0x74; 32])
            .unwrap()
            .with_capacity_profile(profile),
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        opc_consensus::DURABLE_CONSENSUS_OPERATION_TIMEOUT,
    )
    .unwrap();
    let backend =
        SqliteBackend::provision_config_authority(options, AuditKey::new([0x75; 32]).unwrap())
            .await
            .unwrap();
    ConsensusConfigStore::open(topology, backend, root.join("snapshots"), BTreeMap::new())
        .await
        .unwrap()
}

async fn intent(store: &ConsensusConfigStore) -> ConfigMutationIntent {
    let (mut record, _, _) = crate::consensus::store::tests::sized_attested_commit(32).into_parts();
    if store.capacity_profile() == ConfigCapacityProfile::Legacy {
        return ConfigMutationIntent::AppendCommit(Box::new(
            crate::consensus::PreparedConfigCommit::prepare(
                record,
                Vec::new(),
                store.inner.backend.audit_key(),
            )
            .unwrap(),
        ));
    }
    let reservation = store.try_reserve_config_preparation().unwrap().unwrap();
    let aad = opc_key::EnvelopeAad::config(
        opc_types::TenantId::from_static("test"),
        record.version.get(),
        opc_key::ConfigAad::new(
            record.tx_id,
            record.parent_tx_id,
            record.committed_at,
            &record.principal,
            record.schema_digest,
            "running",
        )
        .unwrap(),
    );
    let provider = opc_key::MemoryKeyProvider::new();
    provider
        .insert_active_key(
            opc_key::KeyId::new("synthetic-admission").unwrap(),
            opc_key::KeyPurpose::Config,
            opc_types::TenantId::from_static("test"),
            opc_key::Zeroizing::new([0x76; 32]),
        )
        .unwrap();
    let plaintext = br#"{"synthetic":true}"#;
    let encrypted = opc_crypto::encrypt_reserved_bounded_config_envelope(
        reservation,
        &provider,
        &aad,
        plaintext,
    )
    .await
    .unwrap();
    record.encrypted_blob = encrypted.encoded().to_vec();
    record.plaintext_digest = Sha256::digest(plaintext).to_vec();
    let attested =
        crate::AttestedConfigCommit::try_new(record, Vec::new(), encrypted.claim().unwrap())
            .unwrap();
    drop(encrypted);
    let prepared = store.prepare_capacity_commit(attested).unwrap();
    ConfigMutationIntent::prepared_append(prepared.commit, prepared.resolution, prepared.binding)
}

fn audit_input(intent: &mut ConfigMutationIntent, oversized: bool) {
    let ConfigMutationIntent::BoundedAppend { commit, .. } = intent else {
        panic!("bounded fixture");
    };
    commit.audit.push(crate::AuditRecord {
        tx_id: commit.record.tx_id,
        sequence: 0,
        yang_path: if oversized {
            "x".repeat(256 * 1024)
        } else {
            "/synthetic:path".to_owned()
        },
        op_type: crate::types::AuditOpType::Replace,
        previous_value: None,
        new_value: None,
        redaction_applied: true,
        previous_hash: [0x77; 32],
        entry_hmac: [0x78; 32],
    });
}

fn original_ingress(
    store: &ConsensusConfigStore,
    request_id: ConsensusRequestId,
    intent: &ConfigMutationIntent,
) -> Result<(), PersistError> {
    intent.validate_capacity(
        store.inner.identity,
        store.inner.backend.audit_key(),
        store.capacity_profile(),
    )?;
    preflight_config_command_replication_budget(
        store.inner.identity,
        request_id,
        intent,
        store.capacity_profile(),
    )
    .map_err(ForwardMutationRejection::into_persist_error)
}

fn kind(result: Result<(), PersistError>) -> String {
    format!(
        "{:?}",
        result.expect_err("definitive original refusal").kind()
    )
}

fn budget() -> ForwardedBudget {
    ForwardedBudget {
        remaining_nanos: 10_000_000_000,
    }
}

#[tokio::test]
async fn config_capacity_local_admission_keeps_input_before_admission_and_structural_after_barrier()
{
    let store = store(ConfigCapacityProfile::BoundedV1).await;
    let valid = intent(&store).await;
    let request_id = ConsensusRequestId::new();
    let mut bad_proof = valid.clone();
    let ConfigMutationIntent::BoundedAppend { commit, .. } = &mut bad_proof else {
        panic!("bounded fixture");
    };
    *commit.record.encrypted_blob.last_mut().unwrap() ^= 1;
    let mut oversized = valid.clone();
    audit_input(&mut oversized, true);
    let mut late_structural = valid.clone();
    audit_input(&mut late_structural, false);
    let legacy_shape = match valid.clone() {
        ConfigMutationIntent::BoundedAppend { commit, .. } => {
            ConfigMutationIntent::AppendCommit(commit)
        }
        _ => panic!("bounded fixture"),
    };
    assert!(original_ingress(&store, request_id, &bad_proof).is_err());
    assert!(matches!(
        preflight_config_command_replication_budget(
            store.inner.identity,
            request_id,
            &oversized,
            store.capacity_profile(),
        ),
        Err(ForwardMutationRejection::CommandTooLarge)
    ));
    original_ingress(&store, request_id, &late_structural).unwrap();
    assert!(
        store.require_admission().is_err(),
        "uninitialized native authority"
    );
    let before = store.inner.raft.metrics().borrow().last_log_index;
    for case in [
        valid,
        bad_proof,
        oversized,
        late_structural.clone(),
        legacy_shape,
    ] {
        let expected = kind(
            original_ingress(&store, request_id, &case).and_then(|()| store.require_admission()),
        );
        let local = store
            .submit_owned_request_on_local_leader(request_id, case.clone(), None)
            .await;
        assert_eq!(
            kind(local.map(|_| ())),
            expected,
            "local exact refusal category/order"
        );
        let routed = store
            .submit_owned_request_inner(request_id, case, None)
            .await;
        assert_eq!(
            kind(routed.map(|_| ())),
            expected,
            "routed exact refusal category/order"
        );
    }
    // A transfer with unchanged bytes but excessive Vec capacity must be
    // rejected before a route clone could shrink the allocation and hide it.
    let mut expanded = late_structural.clone();
    let ConfigMutationIntent::BoundedAppend { commit, .. } = &mut expanded else {
        panic!("bounded fixture");
    };
    commit.record.encrypted_blob.reserve_exact(33 * 1024 * 1024);
    let expected = kind(original_ingress(&store, request_id, &expanded));
    let refused = store
        .submit_owned_request_on_local_leader(request_id, expanded, None)
        .await;
    assert_eq!(kind(refused.map(|_| ())), expected);
    assert_eq!(store.inner.raft.metrics().borrow().last_log_index, before);
    store.initialize_cluster().await.unwrap();
    let deadline = tokio::time::Instant::now() + store.inner.operation_timeout;
    store.wait_for_known_leader(deadline).await.unwrap();
    assert!(matches!(
        store.local_read_barrier(deadline).await,
        ReadBarrierReply::Ready(_)
    ));
    let before = store.inner.raft.metrics().borrow().last_log_index;
    let local = store
        .submit_owned_request_on_local_leader(request_id, late_structural.clone(), None)
        .await;
    assert_eq!(
        kind(local.map(|_| ())),
        kind(Err(
            ForwardMutationRejection::InvalidCommand.into_persist_error()
        )),
        "structural refusal stays after the real leadership barrier"
    );
    let received = ForwardMutationRequest {
        request_id,
        intent: late_structural,
        compatibility: store.peer_compatibility(),
        budget: budget(),
    };
    assert!(matches!(
        store
            .apply_owned_on_local_leader(received, deadline, None)
            .await,
        ForwardMutationReply::Rejected(ForwardMutationRejection::InvalidCommand)
    ));
    assert_eq!(store.inner.raft.metrics().borrow().last_log_index, before);
    assert!(store.load_latest().await.unwrap().is_none());
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn config_capacity_local_admission_binds_store_owned_value_and_preserves_received_and_legacy()
{
    let first = store(ConfigCapacityProfile::BoundedV1).await;
    let foreign = store(ConfigCapacityProfile::BoundedV1).await;
    let value = intent(&first).await;
    let request_id = ConsensusRequestId::new();
    let original = serde_json::to_vec(&value).unwrap();
    let input = LocalIntent::new(&first, request_id, value.clone()).unwrap();
    assert!(
        matches!(
            input.local(budget()).validate(&foreign),
            Err(ForwardMutationRejection::InvalidCommand)
        ),
        "another store with identical identity/profile/key still cannot consume local evidence"
    );
    let mut forwarded = input.forward(budget());
    forwarded.request_id = ConsensusRequestId::new();
    let ConfigMutationIntent::BoundedAppend { commit, .. } = &mut forwarded.intent else {
        panic!("bounded fixture");
    };
    *commit.record.encrypted_blob.last_mut().unwrap() ^= 1;
    assert!(matches!(
        LocalMutation::received(forwarded).validate(&first),
        Err(ForwardMutationRejection::InvalidCommand)
    ));
    let cloned_store = first.clone();
    let command = input
        .into_local(budget())
        .validate(&cloned_store)
        .unwrap()
        .finalize(super::super::maximum_encoded_config_timestamp().unwrap())
        .unwrap();
    assert_eq!(command.request_id, request_id);
    assert_eq!(command.identity, first.inner.identity);
    assert_eq!(serde_json::to_vec(&command.intent).unwrap(), original);
    command
        .validate_for_profile(
            first.inner.identity,
            first.inner.backend.audit_key(),
            first.capacity_profile(),
        )
        .unwrap();
    let observation = Observation::new(request_id);
    let received = LocalIntent::new(&first, request_id, value)
        .unwrap()
        .forward(budget());
    LocalMutation::received(received)
        .validate(&first)
        .unwrap()
        .finalize(super::super::maximum_encoded_config_timestamp().unwrap())
        .unwrap();
    let counts = observation.snapshot();
    assert_eq!(
        (
            counts.local_apply.preflight_calls,
            counts.local_apply.capacity_calls
        ),
        (1, 1)
    );
    assert_eq!(
        (counts.preflight_calls, counts.finalized_capacity_calls),
        (1, 1)
    );
    drop(observation);
    let legacy = store(ConfigCapacityProfile::Legacy).await;
    let legacy_value = intent(&legacy).await;
    let observation = Observation::new(request_id);
    LocalIntent::new(&legacy, request_id, legacy_value)
        .unwrap()
        .into_local(budget())
        .validate(&legacy)
        .unwrap()
        .finalize(super::super::maximum_encoded_config_timestamp().unwrap())
        .unwrap();
    let counts = observation.snapshot();
    assert_eq!(
        (
            counts.ingress.capacity_calls,
            counts.local_apply.capacity_calls,
            counts.finalized_capacity_calls
        ),
        (1, 1, 1)
    );
    assert_eq!(
        (
            counts.ingress.preflight_calls,
            counts.local_apply.preflight_calls,
            counts.preflight_calls
        ),
        (0, 0, 0),
        "Legacy retains its original encoder, not the bounded preflight"
    );
    drop(observation);
    legacy.shutdown().await.unwrap();
    foreign.shutdown().await.unwrap();
    first.shutdown().await.unwrap();
}
