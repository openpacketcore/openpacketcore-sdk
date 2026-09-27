//! Real retained native writes observe redundant work at its synchronous call
//! sites. This is neither whole-operation allocation nor transport qualification.

use super::*;
use crate::audit_authority::{
    AuditAdmission, AuditCaller, AuditLedgerLimits, AuditOperationHandle, AuditOperationReceipt,
    AuditOperationState, AuditPrivacyKey,
};
use crate::{AuditKey, RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions};
use opc_crypto::{ConfigCapacityProfile, CONFIG_CAPACITY_V1_LOGICAL_BYTES};

/// Observations are selected by the real command's request ID and installed
/// only during synchronous admission/encoding. They own no command or store.
pub(crate) mod observation {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::{Arc, LazyLock, Mutex, Weak};

    use opc_consensus::engine::{Entry, EntryPayload};
    use opc_consensus::ConsensusRequestId;

    use crate::consensus::ConfigRaftTypeConfig;

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) struct AdmissionCounts {
        pub(crate) scopes: usize,
        pub(crate) preflight_calls: usize,
        pub(crate) preflight_successes: usize,
        pub(crate) capacity_calls: usize,
        pub(crate) capacity_successes: usize,
    }

    #[derive(Clone, Copy, Debug, Default)]
    pub(crate) struct Counts {
        pub(crate) native_canonical_decodes: usize,
        pub(crate) native_fallback_decodes: usize,
        pub(crate) native_canonical_compares: usize,
        pub(crate) native_canonical_compare_writes: usize,
        pub(crate) native_canonical_compare_largest_writes: usize,
        pub(crate) native_canonical_compare_ciphertext_bytes: usize,
        pub(crate) outcome_digest_calls: usize,
        pub(crate) outcome_digest_bytes: usize,
        pub(crate) outcome_digest_updates: usize,
        pub(crate) applied_digest_calls: usize,
        pub(crate) applied_digest_bytes: usize,
        pub(crate) applied_digest_updates: usize,
        pub(crate) effect_verifications: usize,
        pub(crate) effect_serializations: usize,
        pub(crate) effect_encoded_bytes: usize,
        pub(crate) effect_length_writes: usize,
        pub(crate) effect_mac_writes: usize,
        pub(crate) ingress: AdmissionCounts,
        pub(crate) local_apply: AdmissionCounts,
        pub(crate) native_validation: AdmissionCounts,
        pub(crate) finalized_capacity_calls: usize,
        pub(crate) finalized_capacity_successes: usize,
        pub(crate) finalized_scopes: usize,
        pub(crate) preflight_calls: usize,
        pub(crate) preflight_successes: usize,
        pub(crate) append_scopes: usize,
        pub(crate) append_counts: usize,
        pub(crate) append_encoded_bytes: usize,
        pub(crate) append_output_allocations: usize,
        pub(crate) append_output_capacity: usize,
        pub(crate) apply_scopes: usize,
        pub(crate) apply_counts: usize,
        pub(crate) apply_encoded_bytes: usize,
        pub(crate) apply_output_allocations: usize,
        pub(crate) apply_output_capacity: usize,
    }

    #[derive(Clone, Copy)]
    enum Phase {
        Ingress,
        LocalApply,
        NativeValidation,
        Finalized,
        Append,
        Apply,
    }

    type SharedCounts = Arc<Mutex<Counts>>;
    type ActiveScope = (Phase, SharedCounts);
    type Registry = HashMap<ConsensusRequestId, Weak<Mutex<Counts>>>;

    static OBSERVERS: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(HashMap::new()));
    thread_local! {
        static ACTIVE: RefCell<Option<ActiveScope>> = const { RefCell::new(None) };
    }

    pub(crate) struct Observation {
        request_id: ConsensusRequestId,
        counts: SharedCounts,
    }

    impl Observation {
        pub(crate) fn new(request_id: ConsensusRequestId) -> Self {
            let counts = Arc::new(Mutex::new(Counts::default()));
            assert!(OBSERVERS
                .lock()
                .expect("cost observer registry")
                .insert(request_id, Arc::downgrade(&counts))
                .is_none());
            Self { request_id, counts }
        }

        pub(crate) fn snapshot(&self) -> Counts {
            *self.counts.lock().expect("cost counters")
        }
    }

    impl Drop for Observation {
        fn drop(&mut self) {
            let _ = OBSERVERS
                .lock()
                .expect("cost observer registry")
                .remove(&self.request_id);
        }
    }

    pub(crate) struct Scope {
        previous: Option<ActiveScope>,
    }

    impl Scope {
        fn enter(request_id: Option<ConsensusRequestId>, phase: Phase) -> Self {
            let counts = request_id.and_then(|request_id| {
                OBSERVERS
                    .lock()
                    .expect("cost observer registry")
                    .get(&request_id)
                    .and_then(Weak::upgrade)
            });
            if let Some(counts) = &counts {
                let mut counts = counts.lock().expect("cost counters");
                match phase {
                    Phase::Ingress => counts.ingress.scopes += 1,
                    Phase::LocalApply => counts.local_apply.scopes += 1,
                    Phase::NativeValidation => counts.native_validation.scopes += 1,
                    Phase::Finalized => counts.finalized_scopes += 1,
                    Phase::Append => counts.append_scopes += 1,
                    Phase::Apply => counts.apply_scopes += 1,
                }
            }
            let previous = ACTIVE.with(|active| active.replace(counts.map(|c| (phase, c))));
            Self { previous }
        }

        pub(crate) fn ingress(request_id: ConsensusRequestId) -> Self {
            Self::enter(Some(request_id), Phase::Ingress)
        }

        pub(crate) fn local_apply(request_id: ConsensusRequestId) -> Self {
            Self::enter(Some(request_id), Phase::LocalApply)
        }

        pub(crate) fn native_validation(request_id: ConsensusRequestId) -> Self {
            Self::enter(Some(request_id), Phase::NativeValidation)
        }

        pub(crate) fn finalized(request_id: ConsensusRequestId) -> Self {
            Self::enter(Some(request_id), Phase::Finalized)
        }

        fn entry(entry: &Entry<ConfigRaftTypeConfig>, phase: Phase) -> Self {
            let request_id = match &entry.payload {
                EntryPayload::Normal(command) => Some(command.request_id),
                _ => None,
            };
            Self::enter(request_id, phase)
        }

        pub(crate) fn append(entry: &Entry<ConfigRaftTypeConfig>) -> Self {
            Self::entry(entry, Phase::Append)
        }

        pub(crate) fn apply(entry: &Entry<ConfigRaftTypeConfig>) -> Self {
            Self::entry(entry, Phase::Apply)
        }
    }

    impl Drop for Scope {
        fn drop(&mut self) {
            let _ = ACTIVE.with(|active| active.replace(self.previous.take()));
        }
    }

    fn observe(update: impl FnOnce(Phase, &mut Counts)) {
        ACTIVE.with(|active| {
            if let Some((phase, counts)) = active.borrow().as_ref() {
                update(*phase, &mut counts.lock().expect("cost counters"));
            }
        });
    }

    // The real command reports its local SHA counters only after all bytes
    // have been hashed. This owns no payload or store and spans no await.
    pub(crate) fn command_digest(
        request_id: ConsensusRequestId,
        outcome: bool,
        bytes: usize,
        updates: usize,
    ) {
        let counts = OBSERVERS
            .lock()
            .expect("cost observer registry")
            .get(&request_id)
            .and_then(Weak::upgrade);
        if let Some(counts) = counts {
            let mut counts = counts.lock().expect("cost counters");
            if outcome {
                counts.outcome_digest_calls += 1;
                counts.outcome_digest_bytes += bytes;
                counts.outcome_digest_updates += updates;
            } else {
                counts.applied_digest_calls += 1;
                counts.applied_digest_bytes += bytes;
                counts.applied_digest_updates += updates;
            }
        }
    }

    // Measure the real comparison sink only after complete canonical equality.
    // The ciphertext extent comes from its fully checked native input array;
    // the largest write is measured by the sink, not by the formatter branch.
    pub(crate) fn native_canonical_compared(
        entry: &Entry<ConfigRaftTypeConfig>,
        ciphertext_bytes: usize,
        writes: usize,
        largest_write: usize,
    ) {
        let EntryPayload::Normal(command) = &entry.payload else {
            return;
        };
        let counts = OBSERVERS
            .lock()
            .expect("cost observer registry")
            .get(&command.request_id)
            .and_then(Weak::upgrade);
        if let Some(counts) = counts {
            let mut counts = counts.lock().expect("cost counters");
            counts.native_canonical_compares += 1;
            counts.native_canonical_compare_writes += writes;
            counts.native_canonical_compare_largest_writes += largest_write;
            counts.native_canonical_compare_ciphertext_bytes += ciphertext_bytes;
        }
    }

    // A completed real row decode is selected by its actual request ID.
    // This owns neither the entry nor its native store, and spans no await.
    pub(crate) fn native_decoded(entry: &Entry<ConfigRaftTypeConfig>, canonical: bool) {
        let EntryPayload::Normal(command) = &entry.payload else {
            return;
        };
        let counts = OBSERVERS
            .lock()
            .expect("cost observer registry")
            .get(&command.request_id)
            .and_then(Weak::upgrade);
        if let Some(counts) = counts {
            let mut counts = counts.lock().expect("cost counters");
            if canonical {
                counts.native_canonical_decodes += 1;
            } else {
                counts.native_fallback_decodes += 1;
            }
        }
    }

    thread_local! {
        static ACTIVE_EFFECT: RefCell<Option<SharedCounts>> = const { RefCell::new(None) };
    }

    // Select the real effect's handle-derived request ID; no payload is owned,
    // and this guard exists only across one synchronous authentication call.
    pub(crate) struct EffectScope {
        previous: Option<SharedCounts>,
    }

    impl EffectScope {
        pub(crate) fn enter(handle: &crate::audit_authority::AuditOperationHandle) -> Self {
            let request_id = crate::consensus::store::derive_durable_request_id(
                handle.body.identity,
                b"audit-config",
                &handle.mac,
            );
            let counts = OBSERVERS
                .lock()
                .expect("cost observer registry")
                .get(&request_id)
                .and_then(Weak::upgrade);
            if let Some(counts) = &counts {
                counts.lock().expect("cost counters").effect_verifications += 1;
            }
            Self {
                previous: ACTIVE_EFFECT.with(|active| active.replace(counts)),
            }
        }
    }

    impl Drop for EffectScope {
        fn drop(&mut self) {
            let _ = ACTIVE_EFFECT.with(|active| active.replace(self.previous.take()));
        }
    }

    // Called once after real length counting, exact transcript consumption and
    // the final MAC flush. Per-write accounting stays local to the real sinks.
    pub(crate) fn effect_serialized(bytes: usize, length_writes: usize, mac_writes: usize) {
        ACTIVE_EFFECT.with(|active| {
            if let Some(counts) = active.borrow().as_ref() {
                let mut counts = counts.lock().expect("cost counters");
                counts.effect_serializations += 1;
                counts.effect_encoded_bytes += bytes;
                counts.effect_length_writes += length_writes;
                counts.effect_mac_writes += mac_writes;
            }
        });
    }

    fn admission(phase: Phase, counts: &mut Counts) -> Option<&mut AdmissionCounts> {
        match phase {
            Phase::Ingress => Some(&mut counts.ingress),
            Phase::LocalApply => Some(&mut counts.local_apply),
            Phase::NativeValidation => Some(&mut counts.native_validation),
            Phase::Finalized | Phase::Append | Phase::Apply => None,
        }
    }

    pub(crate) fn capacity_validation_started() {
        observe(|phase, counts| {
            if matches!(phase, Phase::Finalized) {
                counts.finalized_capacity_calls += 1;
            } else if let Some(counts) = admission(phase, counts) {
                counts.capacity_calls += 1;
            }
        });
    }

    pub(crate) fn capacity_validation_succeeded() {
        observe(|phase, counts| {
            if matches!(phase, Phase::Finalized) {
                counts.finalized_capacity_successes += 1;
            } else if let Some(counts) = admission(phase, counts) {
                counts.capacity_successes += 1;
            }
        });
    }

    pub(crate) fn preflight_started() {
        observe(|phase, counts| {
            if matches!(phase, Phase::Finalized) {
                counts.preflight_calls += 1;
            } else if let Some(counts) = admission(phase, counts) {
                counts.preflight_calls += 1;
            }
        });
    }

    pub(crate) fn preflight_succeeded() {
        observe(|phase, counts| {
            if matches!(phase, Phase::Finalized) {
                counts.preflight_successes += 1;
            } else if let Some(counts) = admission(phase, counts) {
                counts.preflight_successes += 1;
            }
        });
    }

    pub(crate) fn json_counted(bytes: usize) {
        observe(|phase, counts| match phase {
            Phase::Append => {
                counts.append_counts += 1;
                counts.append_encoded_bytes += bytes;
            }
            Phase::Apply => {
                counts.apply_counts += 1;
                counts.apply_encoded_bytes += bytes;
            }
            Phase::Finalized | Phase::Ingress | Phase::LocalApply | Phase::NativeValidation => {}
        });
    }

    pub(crate) fn json_output_allocated(capacity: usize) {
        observe(|phase, counts| match phase {
            Phase::Append => {
                counts.append_output_allocations += 1;
                counts.append_output_capacity += capacity;
            }
            Phase::Apply => {
                counts.apply_output_allocations += 1;
                counts.apply_output_capacity += capacity;
            }
            Phase::Finalized | Phase::Ingress | Phase::LocalApply | Phase::NativeValidation => {}
        });
    }
}

enum Recovery {
    Ordinary(ConfigCommitRecoveryHandle),
    Audited {
        handle: Box<AuditOperationHandle>,
        caller: AuditCaller,
    },
}

#[tokio::test]
async fn config_capacity_957_native_ordinary_costs_preserve_readback_and_reopen() {
    run_native_cost_case(false, true).await;
}

#[tokio::test]
async fn config_capacity_957_native_audited_costs_preserve_readback_and_reopen() {
    run_native_cost_case(true, true).await;
}

#[tokio::test]
async fn config_capacity_957_native_ordinary_routed_costs_preserve_readback_and_reopen() {
    run_native_cost_case(false, false).await;
}

#[tokio::test]
async fn config_capacity_957_native_audited_routed_costs_preserve_readback_and_reopen() {
    run_native_cost_case(true, false).await;
}

async fn run_native_cost_case(audited: bool, local_only: bool) {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit disk scratch root");
    let root = tempfile::Builder::new()
        .prefix("config-capacity-cost-")
        .tempdir_in(scratch)
        .expect("private disk fixture")
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
    let topology = topology();
    let options = RetainedConfigOptions::new(
        root.join("config.sqlite"),
        RetainedConfigBinding::new(topology.clone(), [0x91; 32], [0x92; 32])
            .expect("retained binding")
            .with_capacity_profile(ConfigCapacityProfile::BoundedV1),
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        DURABLE_CONSENSUS_OPERATION_TIMEOUT,
    )
    .expect("unchanged native limits");
    let key = AuditKey::new([0x93; 32]).expect("synthetic audit key");
    let backend = SqliteBackend::provision_config_authority(options.clone(), key.clone())
        .await
        .expect("native retained backend");
    let store = ConsensusConfigStore::open(
        topology.clone(),
        backend,
        root.join("snapshots"),
        BTreeMap::new(),
    )
    .await
    .expect("profile-bound native store");
    ready(&store).await;
    let privacy = AuditPrivacyKey::new([0x94; 32]).expect("synthetic privacy key");
    if audited {
        store
            .initialize_audit_authority(
                &privacy,
                AuditLedgerLimits::new(6, 2).expect("bounded ledger"),
            )
            .await
            .expect("real ledger initialization");
    }
    let provider = opc_key::MemoryKeyProvider::new();
    provider
        .insert_active_key(
            opc_key::KeyId::new("synthetic-capacity-cost").expect("key ID"),
            opc_key::KeyPurpose::Config,
            opc_types::TenantId::from_static("test"),
            opc_key::Zeroizing::new([0x95; 32]),
        )
        .expect("synthetic provider");
    let reservation = store
        .try_reserve_config_preparation()
        .expect("public destination admission")
        .expect("bounded reservation before input allocation");
    let (mut record, _, _) = sized_attested_commit(32).into_parts();
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
        .expect("synthetic AAD"),
    );
    let plaintext = serde_json::to_vec(&"x".repeat(CONFIG_CAPACITY_V1_LOGICAL_BYTES - 2))
        .expect("at-limit valid JSON");
    assert_eq!(plaintext.len(), CONFIG_CAPACITY_V1_LOGICAL_BYTES);
    let encrypted = opc_crypto::encrypt_reserved_bounded_config_envelope(
        reservation,
        &provider,
        &aad,
        &plaintext,
    )
    .await
    .expect("reserved authenticated encryption");
    record.encrypted_blob = encrypted.encoded().to_vec();
    record.plaintext_digest = Sha256::digest(&plaintext).to_vec();
    let expected = record.clone();
    let commit = AttestedConfigCommit::try_new(
        record,
        Vec::new(),
        encrypted.claim().expect("one-shot encryption claim"),
    )
    .expect("exact attested commit");
    drop(encrypted);
    let (observation, recovery) = if audited {
        let event = audit_event(&expected.principal);
        let caller = AuditCaller::project(&privacy, "test", &expected.principal)
            .expect("independent authenticated caller");
        let prepared = store
            .prepare_audited_commit(&privacy, &event, commit, Duration::from_secs(60))
            .expect("prepare exact audited effect");
        let handle = prepared.handle().clone();
        let admitted = applied(store.admit_audit_operation_local(&handle, caller).await);
        assert_eq!(admitted.state(), AuditOperationState::Intent);
        let request_id =
            derive_durable_request_id(store.inner.identity, b"audit-config", &handle.mac);
        let observation = observation::Observation::new(request_id);
        let admission = if local_only {
            store
                .submit_audited_mutation_local(&prepared, &admitted, caller)
                .await
        } else {
            store
                .submit_audited_mutation(&prepared, &admitted, caller)
                .await
        };
        let receipt = applied(admission);
        assert_eq!(
            receipt.state(),
            AuditOperationState::Committed { version: 1 }
        );
        let terminal = applied(store.finish_audit_operation(&handle, caller).await);
        assert_eq!(terminal.state(), receipt.state());
        assert!(terminal.terminal_recorded());
        (
            observation,
            Recovery::Audited {
                handle: Box::new(handle),
                caller,
            },
        )
    } else {
        let request_id = opc_consensus::ConsensusRequestId::new();
        let operation = store
            .prepare_recoverable_commit(request_id, commit, &expected.principal)
            .expect("prepare exact ordinary effect");
        let handle = operation.recovery_handle().clone();
        let observation = observation::Observation::new(request_id);
        let committed = if local_only {
            store.append_prepared_commit_local(operation).await
        } else {
            store.append_prepared_commit(operation).await
        };
        committed.expect("actual native committed result");
        (observation, Recovery::Ordinary(handle))
    };
    verify(&store, &provider, &aad, &plaintext, &expected, &recovery).await;
    let before_reopen_counts = observation.snapshot();
    store.shutdown().await.expect("join native owners");
    drop(store);
    let backend = SqliteBackend::reopen_config_authority(options, key)
        .await
        .expect("reopen original retained authority");
    let reopened =
        ConsensusConfigStore::open(topology, backend, root.join("snapshots"), BTreeMap::new())
            .await
            .expect("reopen native engine");
    ready(&reopened).await;
    verify(&reopened, &provider, &aad, &plaintext, &expected, &recovery).await;
    reopened.shutdown().await.expect("join reopened owners");
    let counts = observation.snapshot();
    println!("CONFIG_CAPACITY_NATIVE_COST audited={audited} local_only={local_only} logical_bytes={} exact_readback=true authenticated_recovery=true retained_reopen=true counts={counts:?}", plaintext.len());
    assert!(
        counts.native_canonical_decodes > 0 && counts.native_fallback_decodes == 0,
        "CONFIG_CAPACITY_NATIVE_AUDITED_DECODE_RED: ordinary and audited canonical native entries must decode without a discarded fallback, after exact readback and reopen; counts={counts:?}"
    );
    assert_eq!(
        counts.native_canonical_compares, counts.native_canonical_decodes,
        "every real canonical native row comparison is observed"
    );
    assert!(
        counts.native_canonical_compares > before_reopen_counts.native_canonical_compares,
        "the retained reopen independently decodes the original request"
    );
    assert!(
        counts.native_canonical_compare_ciphertext_bytes > plaintext.len()
            && counts.native_canonical_compare_largest_writes
                == counts.native_canonical_compare_ciphertext_bytes,
        "CONFIG_CAPACITY_NATIVE_CANONICAL_SPAN_RED: the real native comparison must reuse each fully validated numeric ciphertext span after exact readback, original-handle recovery and retained reopen; counts={counts:?}"
    );
    for (domain, calls, bytes, updates) in [
        (
            "outcome",
            counts.outcome_digest_calls,
            counts.outcome_digest_bytes,
            counts.outcome_digest_updates,
        ),
        (
            "applied",
            counts.applied_digest_calls,
            counts.applied_digest_bytes,
            counts.applied_digest_updates,
        ),
    ] {
        assert!(
            calls > 0 && bytes > plaintext.len(),
            "real native {domain} digest"
        );
        assert!(
            updates <= bytes / 4096 + calls,
            "CONFIG_CAPACITY_COMMAND_DIGEST_DISPATCH_RED: actual {domain} digest must batch numeric JSON SHA updates after exact readback, original-handle recovery and retained reopen; calls={calls} bytes={bytes} updates={updates}"
        );
    }
    if audited {
        assert!(
            counts.effect_verifications > 0,
            "real audited effect verification"
        );
        assert_eq!(counts.effect_serializations, counts.effect_verifications);
        assert!(counts.effect_encoded_bytes > plaintext.len());
        assert!(
            counts.effect_length_writes < counts.effect_encoded_bytes / 64
                && counts.effect_mac_writes < counts.effect_encoded_bytes / 64,
            "CONFIG_CAPACITY_AUDITED_EFFECT_WRITES_RED: actual authenticated effect must avoid per-number sink dispatch after exact readback and reopen; counts={counts:?}"
        );
    } else {
        assert_eq!(
            (
                counts.effect_verifications,
                counts.effect_serializations,
                counts.effect_encoded_bytes,
                counts.effect_length_writes,
                counts.effect_mac_writes,
            ),
            (0, 0, 0, 0, 0),
            "ordinary native operation is the negative effect-authentication control"
        );
    }
    assert_eq!(
        counts.finalized_scopes, 1,
        "actual finalized command observed"
    );
    assert_eq!(counts.append_scopes, 1, "actual native WAL entry observed");
    assert_eq!(counts.append_counts, 1);
    assert_eq!(
        counts.append_output_allocations, 1,
        "real allocation positive control"
    );
    assert!(counts.append_output_capacity >= counts.append_encoded_bytes);
    assert!(counts.append_encoded_bytes > plaintext.len());
    assert_eq!(counts.apply_scopes, 1, "actual native apply entry observed");
    assert_eq!(
        counts.apply_counts, 1,
        "apply still performs its full size check"
    );
    assert_eq!(counts.apply_encoded_bytes, counts.append_encoded_bytes);
    assert_eq!(
        (counts.apply_output_allocations, counts.apply_output_capacity),
        (0, 0),
        "CONFIG_CAPACITY_APPLY_OUTPUT_RED: native apply must count without allocating discarded JSON"
    );
    let native_before_reopen = observation::AdmissionCounts {
        scopes: 2,
        preflight_calls: 2,
        preflight_successes: 2,
        capacity_calls: 2,
        capacity_successes: 2,
    };
    assert_eq!(
        before_reopen_counts.native_validation, native_before_reopen,
        "both native append and apply fully validate the actual request"
    );
    assert!(
        counts.native_validation.scopes > before_reopen_counts.native_validation.scopes
            && counts.native_validation.preflight_calls == counts.native_validation.scopes
            && counts.native_validation.preflight_successes == counts.native_validation.scopes
            && counts.native_validation.capacity_calls == counts.native_validation.scopes
            && counts.native_validation.capacity_successes == counts.native_validation.scopes,
        "native durable boundaries independently complete full admission; counts={counts:?}"
    );
    let admitted_once = observation::AdmissionCounts {
        scopes: 1,
        preflight_calls: 1,
        preflight_successes: 1,
        capacity_calls: 1,
        capacity_successes: 1,
    };
    let reused = observation::AdmissionCounts {
        scopes: 1,
        ..observation::AdmissionCounts::default()
    };
    assert!(
        counts.ingress == admitted_once
            && counts.local_apply == reused
            && (counts.preflight_calls, counts.preflight_successes) == (0, 0)
            && (counts.finalized_capacity_calls, counts.finalized_capacity_successes) == (0, 0),
        "CONFIG_CAPACITY_LOCAL_ADMISSION_REUSE_RED: one complete owned-input preflight/proof, zero repeated local/final passes, after real readback and retained reopen; counts={counts:?}"
    );
}

async fn ready(store: &ConsensusConfigStore) {
    assert_eq!(store.capacity_profile(), ConfigCapacityProfile::BoundedV1);
    store
        .initialize_cluster()
        .await
        .expect("admitted singleton");
    let deadline = tokio::time::Instant::now() + store.inner.operation_timeout;
    store
        .wait_for_known_leader(deadline)
        .await
        .expect("natural singleton leadership");
    assert!(matches!(
        store.local_read_barrier(deadline).await,
        ReadBarrierReply::Ready(_)
    ));
}

async fn verify(
    store: &ConsensusConfigStore,
    provider: &opc_key::MemoryKeyProvider,
    aad: &opc_key::EnvelopeAad,
    plaintext: &[u8],
    expected: &CommitRecord,
    recovery: &Recovery,
) {
    let before = store.inner.raft.metrics().borrow().last_log_index;
    let actual = store
        .load_latest()
        .await
        .expect("linearizable native read")
        .expect("committed head");
    assert!(
        actual.record == *expected,
        "exact committed encrypted record"
    );
    let decrypted = opc_crypto::decrypt_envelope(provider, aad, &actual.record.encrypted_blob)
        .await
        .expect("decrypt exact native record");
    assert!(
        decrypted.as_slice() == plaintext,
        "exact at-limit plaintext"
    );
    match recovery {
        Recovery::Ordinary(handle) => assert!(matches!(
            store
                .lookup_commit_operation(handle, &expected.principal)
                .await
                .expect("authenticated original ordinary handle"),
            ConfigCommitRecoveryOutcome::Committed
        )),
        Recovery::Audited { handle, caller } => {
            let receipt = store
                .lookup_audit_operation(handle, *caller)
                .await
                .expect("authenticated original audit handle")
                .expect("retained original receipt");
            assert_eq!(receipt.handle(), handle.as_ref());
            assert_eq!(
                receipt.state(),
                AuditOperationState::Committed { version: 1 }
            );
            assert!(receipt.terminal_recorded());
        }
    }
    assert_eq!(
        store.inner.raft.metrics().borrow().last_log_index,
        before,
        "readback and original-handle recovery append no proposal"
    );
}

fn applied(admission: AuditAdmission) -> AuditOperationReceipt {
    match admission {
        AuditAdmission::Applied(receipt) => receipt,
        other => panic!("expected actual durable audit receipt: {other:?}"),
    }
}

fn audit_event(principal: &str) -> crate::ManagementAuditEventRecord {
    crate::ManagementAuditEventRecord::try_new(
        [0x96; 16],
        crate::ManagementAuditInstant::try_new(
            100,
            0,
            1,
            crate::ManagementAuditTimeSourceCode::NodeClock,
        )
        .expect("synthetic event time"),
        "test",
        principal,
        crate::ManagementAuditTransportCode::Gnmi,
        crate::ManagementAuditOperationCode::Update,
        crate::ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:config"],
        Some("synthetic-capacity-cost"),
    )
    .expect("synthetic audit event")
}
