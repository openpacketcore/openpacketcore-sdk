//! Encoder/digest compatibility controls, not larger-profile admission proof.

use super::*;

fn command(intent: ConfigMutationIntent) -> crate::consensus::ConfigConsensusCommand {
    crate::consensus::ConfigConsensusCommand {
        schema_version: crate::consensus::CONFIG_CONSENSUS_COMMAND_VERSION,
        identity: opc_consensus::ConsensusIdentity::new(
            ConfigConsensusClusterId::from_bytes([0x81; 32]),
            ConfigConsensusConfigurationId::from_bytes([0x82; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("synthetic epoch"),
        ),
        request_id: opc_consensus::ConsensusRequestId::from_bytes([0x83; 16]),
        logical_time: maximum_encoded_config_timestamp().expect("maximum encoded time"),
        intent,
    }
}

fn encrypted_intent(bytes: usize) -> ConfigMutationIntent {
    let (record, audit, resolution) = sized_attested_commit(bytes).into_parts();
    assert!(resolution.is_none());
    ConfigMutationIntent::AppendCommit(Box::new(
        PreparedConfigCommit::prepare(
            record,
            audit,
            &crate::AuditKey::new([0x84; 32]).expect("synthetic key"),
        )
        .expect("prepare real encrypted format control"),
    ))
}

#[test]
fn config_capacity_957_counted_command_sizes_keep_exact_legacy_rejection() {
    for bytes in [16, 512, 524_288, 1_048_000, 1_572_864] {
        let command = command(encrypted_intent(bytes));
        command
            .validate(command.identity)
            .expect("valid command format");
        let encoded = encode_bounded(&command).expect("format control fits hard RPC encoder");
        assert_eq!(
            config_command_encoded_size(&command).expect("counted size"),
            encoded.len()
        );
        let expected = encoded.len() <= DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES;
        assert_eq!(config_command_fits_replication_budget(&command), expected);
        assert_eq!(
            preflight_config_command_replication_budget(
                command.identity,
                command.request_id,
                &command.intent
            )
            .is_ok(),
            expected,
            "counting must preserve the original command rejection"
        );
    }

    // Locate the complete encoded command boundary using the unchanged
    // encoder. The encrypted bytes have fixed-width postcard elements here;
    // keep the same varint length range when adding the remaining capacity.
    let baseline_plaintext = 1_000_000;
    let baseline = command(encrypted_intent(baseline_plaintext));
    let baseline_bytes = encode_bounded(&baseline).expect("boundary sizing control");
    let at_limit_plaintext =
        baseline_plaintext + DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES - baseline_bytes.len();
    for extra in [0, 1] {
        let command = command(encrypted_intent(at_limit_plaintext + extra));
        let encoded = encode_bounded(&command).expect("command boundary is below hard RPC limit");
        assert_eq!(
            encoded.len(),
            DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES + extra,
            "fixture must reach the exact complete-command boundary"
        );
        assert_eq!(config_command_fits_replication_budget(&command), extra == 0);
        let expected = if extra == 0 {
            Ok(())
        } else {
            Err(ForwardMutationRejection::CommandTooLarge)
        };
        assert_eq!(
            preflight_config_command_replication_budget(
                command.identity,
                command.request_id,
                &command.intent
            ),
            expected
        );
    }
}

#[test]
fn config_capacity_957_streamed_digests_match_original_canonical_json() {
    let tx_id = opc_types::TxId::new();
    let intents = [
        (1_u16, encrypted_intent(1_572_864)),
        (1, ConfigMutationIntent::MarkConfirmed { tx_id }),
        (2, ConfigMutationIntent::ClearRecoveryRequired { tx_id }),
        (
            1,
            ConfigMutationIntent::CreateRollbackPoint {
                tx_id,
                label: Some(
                    ValidatedRollbackLabel::try_new("capacity-λ-\\\"".into())
                        .expect("escaped label"),
                ),
            },
        ),
    ];
    for (semantic_revision, intent) in intents {
        let command = command(intent);
        command
            .validate(command.identity)
            .expect("valid command format");
        // Retain the pre-change algorithms, including literal domains, as
        // independent compatibility oracles for durable history and outcomes.
        let mut old_payload = Sha256::new();
        old_payload.update(b"openpacketcore/config-consensus/outcome/v1\0");
        old_payload.update(
            serde_json::to_vec(&(semantic_revision, command.identity, &command.intent))
                .expect("original payload JSON"),
        );
        let expected: [u8; 32] = old_payload.finalize().into();
        assert!(
            command.payload_digest().expect("streamed payload") == expected,
            "outcome digest compatibility"
        );

        let sequence = i64::MAX as u64;
        let previous = opc_consensus::ConsensusEntryDigest::from_bytes([0x85; 32]);
        let effective_time = size_test_timestamp();
        let mut old_applied = Sha256::new();
        old_applied.update(b"openpacketcore/config-consensus/command/v1\0");
        old_applied.update(
            serde_json::to_vec(&(sequence, previous, effective_time, &command))
                .expect("original applied JSON"),
        );
        let expected: [u8; 32] = old_applied.finalize().into();
        assert!(
            command
                .calculate_applied_digest(sequence, previous, effective_time)
                .expect("streamed applied")
                .as_bytes()
                == &expected,
            "applied-chain digest compatibility"
        );
    }
}

fn audit_event() -> crate::ManagementAuditEventRecord {
    crate::ManagementAuditEventRecord::try_new(
        [0x86; 16],
        crate::ManagementAuditInstant::try_new(
            100,
            0,
            1,
            crate::ManagementAuditTimeSourceCode::NodeClock,
        )
        .expect("synthetic event time"),
        "test",
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0",
        crate::ManagementAuditTransportCode::Gnmi,
        crate::ManagementAuditOperationCode::Update,
        crate::ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:config"],
        Some("synthetic-command-boundary"),
    )
    .expect("synthetic boundary event")
}

// Encoding oracle only: build a valid complete audited command without calling
// the preparation guard being tested. This must remain independent of that guard.
fn audited_boundary_command(
    store: &ConsensusConfigStore,
    bytes: usize,
) -> crate::consensus::ConfigConsensusCommand {
    use crate::audit_authority::ledger::HandleBody;
    use crate::audit_authority::{
        AuditOperationBinding, AuditOperationHandle, AuditPrivacyKey, ProjectedAuditEvent,
    };
    use crate::consensus::audit_mutation::AuditedConfigEffect;

    let key = store.inner.backend.audit_key();
    let privacy = AuditPrivacyKey::new([0x87; 32]).expect("synthetic privacy key");
    let (record, audit, resolution) = sized_attested_commit(bytes).into_parts();
    let effect = AuditedConfigEffect::Append {
        commit: Box::new(PreparedConfigCommit::prepare(record, audit, key).expect("valid record")),
        resolution,
    };
    let digest = effect.digest(key).expect("authenticated exact effect");
    let event = ProjectedAuditEvent::project(&privacy, &audit_event()).expect("project event");
    let binding = AuditOperationBinding::project(&privacy, &event, 0, &digest)
        .expect("project exact binding");
    let issued_at = store
        .inner
        .clock
        .now_utc()
        .as_offset_datetime()
        .unix_timestamp();
    let handle = AuditOperationHandle::issue(
        HandleBody {
            version: 1,
            identity: store.inner.identity,
            binding,
            event,
            issued_at,
            expires_at: issued_at.checked_add(60).expect("fixture lifetime"),
            nonce: [0x88; 16],
            key_epoch: key.epoch(),
            mutation: Some(digest),
        },
        key,
    )
    .expect("valid authenticated handle");
    let request_id = derive_durable_request_id(store.inner.identity, b"audit-config", &handle.mac);
    crate::consensus::ConfigConsensusCommand {
        schema_version: crate::consensus::CONFIG_CONSENSUS_COMMAND_VERSION,
        identity: store.inner.identity,
        request_id,
        logical_time: maximum_encoded_config_timestamp().expect("maximum leader timestamp"),
        intent: ConfigMutationIntent::AuditedMutation(
            crate::consensus::PreparedAuditedMutation::new(handle, effect, None)
                .command()
                .clone(),
        ),
    }
}

#[tokio::test]
async fn config_capacity_957_audit_metadata_counts_at_exact_command_boundary() {
    // The unit fixture isolates exact postcard sizing and preparation. The
    // separate native-Durable integration detector establishes durable effects.
    let (store, _snapshots) = singleton_store().await;
    let baseline_plaintext = 1_000_000;
    let baseline = audited_boundary_command(&store, baseline_plaintext);
    baseline
        .validate(store.inner.identity)
        .expect("valid size oracle");
    let baseline_len = encode_bounded(&baseline)
        .expect("real postcard oracle")
        .len();
    let at_limit_plaintext = baseline_plaintext
        + DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES
            .checked_sub(baseline_len)
            .expect("baseline command below unchanged limit");
    let privacy =
        crate::audit_authority::AuditPrivacyKey::new([0x87; 32]).expect("synthetic privacy key");
    for extra in [0, 1] {
        let oracle = audited_boundary_command(&store, at_limit_plaintext + extra);
        oracle
            .validate(store.inner.identity)
            .expect("valid exact command oracle");
        assert_eq!(
            encode_bounded(&oracle)
                .expect("real complete-command encoding")
                .len(),
            DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES + extra,
            "fixture reaches the exact complete audited-command boundary",
        );
        let ConfigMutationIntent::AuditedMutation(ref audited) = oracle.intent else {
            panic!("audited fixture");
        };
        let mut inner = oracle.clone();
        inner.intent = audited.effect.intent();
        assert!(
            encode_bounded(&inner)
                .expect("real inner-command encoding")
                .len()
                < DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES,
            "inner effect alone must fit in both adversarial cases",
        );
        let result = store.prepare_audited_commit(
            &privacy,
            &audit_event(),
            sized_attested_commit(at_limit_plaintext + extra),
            Duration::from_secs(60),
        );
        if extra == 0 {
            let prepared = result.expect("complete command at limit is accepted");
            let accepted = crate::consensus::ConfigConsensusCommand {
                request_id: derive_durable_request_id(
                    store.inner.identity,
                    b"audit-config",
                    &prepared.handle().mac,
                ),
                intent: ConfigMutationIntent::AuditedMutation(prepared.command().clone()),
                ..oracle
            };
            assert_eq!(
                encode_bounded(&accepted)
                    .expect("actual prepared command encoding")
                    .len(),
                DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES,
                "preparation preserves the exact at-limit command",
            );
        } else {
            assert!(
                matches!(result, Err(crate::audit_authority::AuditAuthorityError::InvalidInput)),
                "CONFIG_CAPACITY_AUDIT_METADATA_RED: complete audited command one byte over must reject during preparation",
            );
        }
    }
    store.shutdown().await.expect("shutdown encoding fixture");
}

fn check_audited_validation(command: &crate::consensus::ConfigConsensusCommand, valid: bool) {
    let ConfigMutationIntent::AuditedMutation(prepared) = &command.intent else {
        panic!("audited validation fixture");
    };
    // Retain the previous owned-inner-command path as a compatibility oracle.
    // This fixture measures validation semantics, not process allocations.
    let original = crate::consensus::ConfigConsensusCommand {
        intent: prepared.effect.intent(),
        ..command.clone()
    };
    let before = serde_json::to_vec(command).expect("format fixture before validation");
    let decoded: crate::consensus::ConfigConsensusCommand =
        serde_json::from_slice(&before).expect("untrusted command field decoding");
    let result = decoded.validate(command.identity);
    assert_eq!(result.is_ok(), valid, "audited effect format admission");
    assert!(
        match (result, original.validate(command.identity)) {
            (Ok(()), Ok(())) => true,
            (Err(actual), Err(expected)) => actual.to_string() == expected.to_string(),
            _ => false,
        },
        "borrowed validation must retain the original inner result and error",
    );
    assert!(
        serde_json::to_vec(&decoded).expect("format fixture after validation") == before,
        "validation must leave the exact encoded command unchanged",
    );
}

#[tokio::test]
async fn config_capacity_957_borrowed_audit_validation_preserves_effect_checks() {
    use crate::consensus::audit_mutation::AuditedConfigEffect;

    let (store, _snapshots) = singleton_store().await;
    let mut fixture = audited_boundary_command(&store, 1_572_864);
    check_audited_validation(&fixture, true);
    let ConfigMutationIntent::AuditedMutation(prepared) = &fixture.intent else {
        panic!("audited fixture");
    };
    let AuditedConfigEffect::Append { commit, .. } = &prepared.effect else {
        panic!("append fixture");
    };
    let original = commit.clone();
    let tx_id = original.record.tx_id;

    // Untrusted decoding must not bypass envelope, finalized-audit, principal,
    // plaintext-digest or confirmed-parent structure checks.
    let corruptions: [fn(&mut PreparedConfigCommit); 4] = [
        |commit| commit.record.encrypted_blob.clear(),
        |commit| commit.record.plaintext_digest.clear(),
        |commit| commit.record.principal.clear(),
        |commit| {
            commit.audit.push(crate::AuditRecord {
                tx_id: commit.record.tx_id,
                sequence: 1,
                yang_path: "/fixture:config".into(),
                op_type: crate::types::AuditOpType::Update,
                previous_value: None,
                new_value: None,
                redaction_applied: true,
                previous_hash: [0; 32],
                entry_hmac: [0x91; 32],
            });
        },
    ];
    for corrupt in corruptions {
        let mut commit = original.clone();
        corrupt(&mut commit);
        let ConfigMutationIntent::AuditedMutation(prepared) = &mut fixture.intent else {
            panic!("audited fixture");
        };
        prepared.effect = AuditedConfigEffect::Append {
            commit,
            resolution: None,
        };
        check_audited_validation(&fixture, false);
    }
    let ConfigMutationIntent::AuditedMutation(prepared) = &mut fixture.intent else {
        panic!("audited fixture");
    };
    prepared.effect = AuditedConfigEffect::Append {
        commit: original,
        resolution: Some(crate::ConfirmedCommitResolution::Confirm {
            pending_tx_id: tx_id,
        }),
    };
    check_audited_validation(&fixture, false);

    for (label, valid) in [
        (None, true),
        (Some("x".repeat(128)), true),
        (Some("x".repeat(129)), false),
        (Some(String::new()), false),
        (Some("invalid\nlabel".into()), false),
    ] {
        let ConfigMutationIntent::AuditedMutation(prepared) = &mut fixture.intent else {
            panic!("audited fixture");
        };
        prepared.effect = AuditedConfigEffect::RollbackPoint {
            tx_id,
            label: label.map(ValidatedRollbackLabel),
        };
        check_audited_validation(&fixture, valid);
    }
    let ConfigMutationIntent::AuditedMutation(prepared) = &mut fixture.intent else {
        panic!("audited fixture");
    };
    prepared.effect = AuditedConfigEffect::Confirm { tx_id };
    // Revision 8 is structurally recognized for the bounded profile. Keep the
    // legacy authority's original revision fence, and reject unknown revision 9
    // at both structural and admitted-profile boundaries.
    for revision in 1..=9 {
        fixture.schema_version = revision;
        assert_eq!(
            fixture.validate(fixture.identity).is_ok(),
            (5..=8).contains(&revision),
            "outer audit revision must be structurally supported",
        );
        assert_eq!(
            fixture
                .validate_for_profile(
                    fixture.identity,
                    store.inner.backend.audit_key(),
                    opc_crypto::ConfigCapacityProfile::Legacy,
                )
                .is_ok(),
            (5..=7).contains(&revision),
            "outer audit revision fence remains authoritative for legacy admission",
        );
        assert_eq!(
            fixture
                .validate_for_profile(
                    fixture.identity,
                    store.inner.backend.audit_key(),
                    opc_crypto::ConfigCapacityProfile::BoundedV1,
                )
                .is_ok(),
            (5..=8).contains(&revision),
            "bounded admission supports only recognized outer audit revisions",
        );
    }
    fixture.schema_version = crate::consensus::CONFIG_CONSENSUS_COMMAND_VERSION;
    check_audited_validation(&fixture, true);
    let other_identity = opc_consensus::ConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0x92; 32]),
        fixture.identity.configuration_id(),
        fixture.identity.configuration_epoch(),
    );
    assert!(
        fixture.validate(other_identity).is_err(),
        "scope remains bound"
    );
    store.shutdown().await.expect("shutdown validation fixture");
}
