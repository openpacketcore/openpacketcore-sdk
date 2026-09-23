//! Native disk Durable singleton rejection through the actual store/handler.
//! Direct handler injection is not authenticated multi-node transport proof.

use super::*;
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::consensus::{ConfigConsensusCommand, ConfigConsensusRequestId};
use opc_consensus::engine::{CommittedLeaderId, Entry, EntryPayload, LogId};

fn bound_successor(store: &ConsensusConfigStore, parent: opc_types::TxId) -> ConfigMutationIntent {
    let (mut record, _, _) = super::super::tests::sized_attested_commit(32).into_parts();
    record.parent_tx_id = Some(parent);
    record.version = opc_types::ConfigVersion::new(2);
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
        .expect("synthetic bound successor AAD"),
    );
    let handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("capacity-command-native").expect("synthetic key ID"),
        opc_key::KeyPurpose::Config,
        opc_types::TenantId::from_static("test"),
        opc_key::Zeroizing::new([0xD1; 32]),
    );
    let plaintext = br#"{"capacity":true}"#;
    let envelope = opc_crypto::encrypt_bounded_config_envelope_with_handle_and_nonce(
        &handle, &aad, plaintext, [0xD2; 12],
    )
    .expect("genuine bounded encryption");
    record.encrypted_blob = envelope.encoded().to_vec();
    record.plaintext_digest = Sha256::digest(plaintext).to_vec();
    let attested =
        AttestedConfigCommit::try_new(record, Vec::new(), envelope.claim().expect("claim"))
            .expect("paired evidence");
    let binding = CapacityRecordBinding::issue(
        &attested,
        store.inner.identity,
        store.inner.backend.audit_key(),
        ConfigCapacityProfile::BoundedV1,
    )
    .expect("genuine scoped proof");
    let (record, audit, resolution) = attested.into_parts();
    ConfigMutationIntent::prepared_append(
        PreparedConfigCommit::prepare(record, audit, store.inner.backend.audit_key())
            .expect("prepared successor"),
        resolution,
        Some(binding),
    )
}

async fn assert_unchanged(
    store: &ConsensusConfigStore,
    record: &CommitRecord,
    before_counts: [i64; 5],
    before_status: &ConfigConsensusStatus,
) {
    assert_eq!(
        counts(store).await,
        before_counts,
        "durable effect counts unchanged"
    );
    let after = store.status();
    assert_eq!(
        after.term, before_status.term,
        "rejection precedes engine vote effects"
    );
    assert_eq!(after.applied_index, before_status.applied_index);
    assert_eq!(after.committed_index, before_status.committed_index);
    assert!(
        &store
            .load_latest()
            .await
            .expect("read")
            .expect("head")
            .record
            == record,
        "exact committed record unchanged"
    );
}

#[tokio::test]
async fn config_capacity_957_bound_local_and_forwarded_proposals_refuse_legacy_authority_before_effects(
) {
    let (store, _root) = native_singleton().await;
    let before = store
        .load_latest()
        .await
        .expect("read control")
        .expect("head");
    let before_counts = counts(&store).await;
    let before_status = store.status();
    let intent = bound_successor(&store, before.record.tx_id);
    let request_id = ConfigConsensusRequestId::from_bytes([0xD3; 16]);
    assert!(store
        .submit_request_inner(request_id, intent.clone())
        .await
        .is_err());
    assert_unchanged(&store, &before.record, before_counts, &before_status).await;
    assert!(store
        .submit_request_on_local_leader(request_id, intent.clone())
        .await
        .is_err());
    assert_unchanged(&store, &before.record, before_counts, &before_status).await;

    let sender = store.inner.local_node_id;
    let payload = encode_config_wire_for_profile(
        ConfigCapacityProfile::Legacy,
        &ForwardMutationRequest {
            request_id,
            intent,
            compatibility: store.peer_compatibility(),
            budget: ForwardedBudget {
                remaining_nanos: 2_000_000_000,
            },
        },
    )
    .expect("matching legacy wire frame carrying unsupported effect");
    let response = store
        .rpc_handler()
        .handle(
            sender,
            ConsensusWireRequest::try_new(
                store.inner.identity,
                sender,
                ConsensusRpcFamily::ForwardMutation,
                payload,
            )
            .expect("matching outer scope"),
        )
        .await;
    let reply: ForwardMutationReply = decode_config_wire_for_profile(
        ConfigCapacityProfile::Legacy,
        &response.result.expect("typed service reply"),
    )
    .expect("decode reply");
    assert!(matches!(
        reply,
        ForwardMutationReply::Rejected(ForwardMutationRejection::InvalidCommand)
    ));
    assert_unchanged(&store, &before.record, before_counts, &before_status).await;
    store.shutdown().await.expect("shutdown native fixture");
}

#[tokio::test]
async fn config_capacity_957_bound_replication_refuses_before_native_vote_and_wal_effects() {
    let (store, _root) = native_singleton().await;
    let before = store
        .load_latest()
        .await
        .expect("read control")
        .expect("head");
    let before_counts = counts(&store).await;
    let before_status = store.status();
    let sender = store.inner.local_node_id;
    let command = ConfigConsensusCommand {
        schema_version: 8,
        identity: store.inner.identity,
        request_id: ConfigConsensusRequestId::from_bytes([0xD4; 16]),
        logical_time: store.inner.clock.now_utc(),
        intent: bound_successor(&store, before.record.tx_id),
    };
    command
        .validate_for_profile(
            store.inner.identity,
            store.inner.backend.audit_key(),
            ConfigCapacityProfile::BoundedV1,
        )
        .expect("valid private proof for a different admitted profile");
    let request = AppendEntriesRequest::<ConfigRaftTypeConfig> {
        vote: Vote::new_committed(before_status.term + 1, sender),
        prev_log_id: None,
        entries: vec![Entry {
            log_id: LogId::new(CommittedLeaderId::new(before_status.term + 1, sender), 1),
            payload: EntryPayload::Normal(command),
        }],
        leader_commit: None,
    };
    let payload = encode_config_wire_for_profile(ConfigCapacityProfile::Legacy, &request)
        .expect("matching wire frame does not grant record profile");
    let response = store
        .rpc_handler()
        .handle(
            sender,
            ConsensusWireRequest::try_new(
                store.inner.identity,
                sender,
                ConsensusRpcFamily::AppendEntries,
                payload,
            )
            .expect("matching outer scope"),
        )
        .await;
    assert!(
        matches!(response.result, Err(ConsensusPeerError::Rejected)),
        "reject before engine handoff"
    );
    assert_unchanged(&store, &before.record, before_counts, &before_status).await;
    store.shutdown().await.expect("shutdown native fixture");
}
