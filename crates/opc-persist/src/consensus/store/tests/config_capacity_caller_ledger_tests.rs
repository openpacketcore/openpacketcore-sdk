//! A public audited caller must release its authenticated preflight ledger
//! before native apply allocates an independent ledger. This observes real
//! payload capacities; it does not measure allocator/RSS or transport buffers.
//! The continuity case also includes the real retained signing rows and their
//! encoded SQL owner through native apply, with mandatory external checkpoints.

use super::*;
use crate::audit_authority::continuity::chain::{ContinuityState, SignedAuditRow};
use crate::audit_authority::continuity::checkpoint::CheckpointBody;
use crate::audit_authority::continuity::{
    AuditCheckpoint, AuditCheckpointAdvance, AuditCheckpointPort, AuditContinuityPolicy,
    AuditKeyRing, AuditKeyTransition, AuditSigningKey,
};
use crate::audit_authority::ledger::{HandleBody, LedgerState};
use crate::audit_authority::{
    AuditAdmission, AuditAuthorityError, AuditCaller, AuditLedgerLimits, AuditOperationBinding,
    AuditOperationHandle, AuditOperationReceipt, AuditOperationState, AuditPrivacyKey,
    AuditPrivacyProjection, AuditPrivacyPurpose, PreparedAuditedMutation, ProjectedAuditEvent,
};
use crate::consensus::audit_mutation::{
    AuditedConfigCommand, AuditedConfigEffect, AuditedMutationFields,
};
use crate::consensus::config_capacity_simultaneous_working_tests::ledger::Sample;
use crate::consensus::ConfigConsensusIdentity;
use crate::{AuditKey, RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions};
use opc_crypto::ConfigCapacityProfile;
use opc_key::{ConfigAad, EnvelopeAad, KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use std::mem::size_of;

#[cfg(feature = "dangerous-test-hooks")]
struct BridgeOracles {
    census: Arc<crate::config_capacity_observation::PreparationCensus>,
    result: std::sync::Mutex<(usize, usize, usize)>,
    derived: std::sync::Mutex<DerivedBridgeOracle>,
}

#[cfg(feature = "dangerous-test-hooks")]
#[derive(Clone, Copy, Debug, Default)]
struct DerivedBridgeOracle {
    callbacks: usize,
    capacity_bytes: usize,
    selected_bytes: usize,
    expected_selected_bytes: usize,
    node_bytes: usize,
    expected_node_bytes: usize,
    matched_oracles: usize,
}

#[cfg(feature = "dangerous-test-hooks")]
impl crate::config_capacity_observation::NativeOwnerObserver for BridgeOracles {
    fn observe(&self, sample: crate::config_capacity_observation::NativeOwnerSample) {
        // This permitted metadata-only callback reenters the public counter
        // read while the real native sample holds its preparation drop barrier.
        // A counter-lock removal control must run in its own exact test process.
        println!(
            "CONFIG_CAPACITY_NATIVE_COUNTER_READ_ENTER stage={:?}",
            sample.stage
        );
        let counters = self.census.snapshot();
        let derived =
            crate::consensus::config_capacity_simultaneous_working_tests::ledger::live_derived_bytes();
        let validation_index =
            crate::consensus::config_capacity_simultaneous_working_tests::ledger::live_validation_index_bytes();
        if derived != 0 {
            // The existing component observer is inside the real validate()
            // scope. No returned ledger or historical peak can satisfy this.
            let mut result = self.derived.lock().unwrap();
            result.callbacks += 1;
            result.capacity_bytes = derived;
            result.selected_bytes = sample.selected_mutation_bytes;
            result.expected_selected_bytes = sample.selected_prepared_bytes
                + sample.native_command_bytes
                + sample.native_ledger_bytes
                + sample.native_write_bytes
                + derived
                + validation_index;
            result.node_bytes = sample.node_mutation_bytes;
            result.expected_node_bytes = sample.node_prepared_bytes
                + sample.native_command_bytes
                + sample.native_ledger_bytes
                + sample.native_write_bytes
                + derived
                + validation_index;
            result.matched_oracles += usize::from(
                counters == sample.preparations
                    && sample.native_is_distinct
                    && validation_index > 0
                    && sample.native_validation_index_bytes == validation_index
                    && sample.independent_oracles_match,
            );
            return;
        }
        let mut result = self.result.lock().unwrap();
        result.0 += 1;
        result.1 += usize::from(sample.independent_oracles_match);
        result.2 += usize::from(
            counters == sample.preparations
                && counters.registrations == 1
                && counters.commands == 1,
        );
    }
}

const OPERATION_BYTES: usize = 33_554_432;
const METADATA_BYTES: usize = 196_608;
// The public signing-key constructor admits every nonzero epoch through i64::MAX.
const CONTINUITY_EPOCH: u64 = i64::MAX as u64;

fn continuity_keys(expanded: bool) -> AuditKeyRing {
    let first = initial_epoch(expanded);
    AuditKeyRing::new(
        (first..=CONTINUITY_EPOCH)
            .map(|epoch| {
                let mut material = [0x9C; 32];
                if expanded {
                    material[0] = (epoch - first) as u8;
                }
                AuditSigningKey::new(epoch, material).expect("distinct retained signing key")
            })
            .collect(),
    )
    .expect("one or eight admitted signing epochs")
}

fn initial_epoch(expanded: bool) -> u64 {
    CONTINUITY_EPOCH - if expanded { 7 } else { 0 }
}

fn transition_rows(expanded: bool) -> usize {
    if expanded {
        7
    } else {
        0
    }
}

// A separate monotonic authority, outside the SQLite restore domain. It keeps
// full opaque checkpoints and compares the exact prior value, not just sequence.
struct ExternalCheckpointFixture {
    identity: ConfigConsensusIdentity,
    expanded: bool,
    value: std::sync::Mutex<Option<AuditCheckpoint>>,
}

impl ExternalCheckpointFixture {
    fn new(identity: ConfigConsensusIdentity, expanded: bool) -> Self {
        Self {
            identity,
            expanded,
            value: std::sync::Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl AuditCheckpointPort for ExternalCheckpointFixture {
    async fn load(
        &self,
        identity: ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        if identity != self.identity {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(self.value.lock().expect("external checkpoint").clone())
    }

    async fn compare_advance(
        &self,
        identity: ConfigConsensusIdentity,
        expected: Option<AuditCheckpoint>,
        next: AuditCheckpoint,
    ) -> Result<AuditCheckpointAdvance, AuditAuthorityError> {
        if identity != self.identity {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let mut current = self.value.lock().expect("external checkpoint");
        if *current != expected
            || current
                .as_ref()
                .is_some_and(|old| old.sequence() >= next.sequence())
        {
            return Ok(AuditCheckpointAdvance::Conflict);
        }
        *current = Some(next);
        Ok(AuditCheckpointAdvance::Applied)
    }
}

fn continuity_policy(external: &Arc<ExternalCheckpointFixture>) -> AuditContinuityPolicy {
    AuditContinuityPolicy::new(
        continuity_keys(external.expanded),
        external.clone(),
        initial_epoch(external.expanded),
        1,
    )
    .expect("independent checkpoint policy at original export limit")
}

async fn checkpoint_retained_prefix(
    prefix: &mut LedgerState,
    external: &Arc<ExternalCheckpointFixture>,
) {
    let keys = continuity_keys(external.expanded);
    prefix
        .validate_continuity(Some(&keys))
        .expect("verify every genuine retained signature");
    let chain = prefix.continuity.as_ref().expect("signed prefix");
    assert_eq!(chain.rows.len(), 3069 + transition_rows(external.expanded));
    let checkpoint = AuditCheckpoint::issue(
        &keys,
        CheckpointBody {
            version: 1,
            identity: prefix.identity,
            sequence: prefix.sequence,
            root_anchor: prefix.terminal,
            anchor: chain.terminal,
            epoch_at_sequence: chain.active_epoch,
            signing_epoch: chain.active_epoch,
            acknowledged_export: [0; 32],
        },
    )
    .expect("authenticate the exact completed prefix");
    assert_eq!(
        external
            .compare_advance(prefix.identity, None, checkpoint.clone())
            .await
            .expect("component checkpoint CAS"),
        AuditCheckpointAdvance::Applied
    );
    assert_eq!(
        external.load(prefix.identity).await.expect("CAS readback"),
        Some(checkpoint)
    );
}

async fn open_fixture(
    topology: ConfigConsensusTopology,
    backend: SqliteBackend,
    snapshots: std::path::PathBuf,
    external: Option<&Arc<ExternalCheckpointFixture>>,
) -> ConsensusConfigStore {
    match external {
        Some(external) => {
            ConsensusConfigStore::open_with_audit_continuity(
                topology,
                backend,
                snapshots,
                BTreeMap::new(),
                continuity_policy(external),
            )
            .await
        }
        None => ConsensusConfigStore::open(topology, backend, snapshots, BTreeMap::new()).await,
    }
    .expect("full native validation of retained identity, state and required continuity")
}

async fn verify_continuity(
    store: &ConsensusConfigStore,
    external: &Arc<ExternalCheckpointFixture>,
) {
    let ledger = store
        .read_audit_ledger()
        .await
        .expect("real quorum read validates independent continuity");
    let checkpoint = external
        .load(store.inner.identity)
        .await
        .expect("independent checkpoint read")
        .expect("required checkpoint");
    checkpoint
        .verify(&continuity_keys(external.expanded), store.inner.identity)
        .expect("authenticate exact independent checkpoint identity");
    ledger
        .matches_checkpoint(&checkpoint)
        .expect("same retained prefix and independent signature anchor");
    let chain = ledger.continuity.as_ref().expect("required signed state");
    assert_eq!(
        ledger.sequence,
        3072 + transition_rows(external.expanded) as u64
    );
    assert_eq!(chain.active_epoch, CONTINUITY_EPOCH);
    assert_eq!(ledger.operations.len(), 1024);
    assert_eq!(ledger.entries.len(), chain.rows.len());
    assert_eq!(checkpoint.sequence(), ledger.sequence);
    assert_eq!(chain.checkpoint.as_ref(), Some(&checkpoint));
}

/// The registry retains counters only. The wrapper owns the very ledger moved
/// out of the real quorum read, without cloning it or changing its drop scope.
pub(crate) mod observation {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::ops::Deref;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, LazyLock, Mutex, Weak};

    use opc_consensus::engine::{Entry, EntryPayload};
    use opc_consensus::ConsensusRequestId;

    use crate::audit_authority::ledger::LedgerState;
    use crate::consensus::config_capacity_simultaneous_working_tests::ledger::{
        self, Observation, ObservationGuard, Sample,
    };
    use crate::consensus::{ConfigMutationIntent, ConfigRaftTypeConfig};

    struct Shared {
        base: Sample,
        original_payload: usize,
        expected_entries: usize,
        caller_bytes: AtomicUsize,
        caller_reads: AtomicUsize,
        caller_drops: AtomicUsize,
        native_calls: AtomicUsize,
        result: Mutex<Option<Observation>>,
    }

    type Registry = HashMap<ConsensusRequestId, Weak<Shared>>;
    static OBSERVERS: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(HashMap::new()));
    thread_local! {
        static ACTIVE: RefCell<Option<Arc<Shared>>> = const { RefCell::new(None) };
    }

    fn find(request: ConsensusRequestId) -> Option<Arc<Shared>> {
        OBSERVERS
            .lock()
            .expect("caller ledger registry")
            .get(&request)
            .and_then(Weak::upgrade)
    }

    pub(crate) struct Registration {
        request: ConsensusRequestId,
        shared: Arc<Shared>,
    }

    impl Registration {
        pub(crate) fn new(
            request: ConsensusRequestId,
            base: Sample,
            prepared: &crate::consensus::audit_mutation::AuditedConfigCommand,
            expected_entries: usize,
        ) -> Self {
            let shared = Arc::new(Shared {
                base,
                original_payload: std::ptr::from_ref(&**prepared) as usize,
                expected_entries,
                caller_bytes: AtomicUsize::new(0),
                caller_reads: AtomicUsize::new(0),
                caller_drops: AtomicUsize::new(0),
                native_calls: AtomicUsize::new(0),
                result: Mutex::new(None),
            });
            assert!(OBSERVERS
                .lock()
                .expect("caller ledger registry")
                .insert(request, Arc::downgrade(&shared))
                .is_none());
            Self { request, shared }
        }

        pub(crate) fn finish(&self) -> Observation {
            assert_eq!(self.shared.caller_reads.load(Ordering::SeqCst), 1);
            assert_eq!(self.shared.caller_drops.load(Ordering::SeqCst), 1);
            assert_eq!(self.shared.caller_bytes.load(Ordering::SeqCst), 0);
            assert_eq!(self.shared.native_calls.load(Ordering::SeqCst), 1);
            self.shared
                .result
                .lock()
                .expect("native ledger result")
                .expect("actual native apply completed its observation")
        }
    }

    impl Drop for Registration {
        fn drop(&mut self) {
            OBSERVERS
                .lock()
                .expect("caller ledger registry")
                .remove(&self.request);
        }
    }

    pub(crate) struct CallerLedger {
        ledger: LedgerState,
        shared: Option<Arc<Shared>>,
    }

    impl CallerLedger {
        pub(crate) fn observe(request: ConsensusRequestId, ledger: LedgerState) -> Self {
            let shared = find(request);
            if let Some(shared) = &shared {
                let bytes = ledger::ledger_heap(&ledger);
                assert_eq!(
                    ledger.operations.len(),
                    1024,
                    "real admitted operation ceiling"
                );
                assert_eq!(
                    ledger.entries.len(),
                    shared.expected_entries,
                    "real retained transition prefix"
                );
                assert!(bytes > 0);
                assert_eq!(shared.caller_bytes.swap(bytes, Ordering::SeqCst), 0);
                shared.caller_reads.fetch_add(1, Ordering::SeqCst);
            }
            Self { ledger, shared }
        }
    }

    impl Deref for CallerLedger {
        type Target = LedgerState;

        fn deref(&self) -> &Self::Target {
            &self.ledger
        }
    }

    impl Drop for CallerLedger {
        fn drop(&mut self) {
            if let Some(shared) = &self.shared {
                // Stop observing before Rust drops the actual ledger fields.
                // Neither the registry nor the SQL observer retains this owner.
                shared.caller_bytes.store(0, Ordering::SeqCst);
                shared.caller_drops.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    pub(crate) fn current_bytes() -> usize {
        ACTIVE.with(|slot| {
            slot.borrow()
                .as_ref()
                .map_or(0, |shared| shared.caller_bytes.load(Ordering::SeqCst))
        })
    }

    pub(crate) struct NativeApply {
        shared: Arc<Shared>,
        guard: Option<ObservationGuard>,
    }

    impl NativeApply {
        pub(crate) fn start(entries: &Vec<Entry<ConfigRaftTypeConfig>>) -> Option<Self> {
            let (command, shared) = entries.iter().find_map(|entry| {
                let EntryPayload::Normal(command) = &entry.payload else {
                    return None;
                };
                find(command.request_id).map(|shared| (command, shared))
            })?;
            assert_eq!(
                entries.len(),
                1,
                "the measured page contains the exact submitted entry"
            );
            let ConfigMutationIntent::AuditedMutation(prepared) = &command.intent else {
                panic!("registered public audited effect");
            };
            assert_ne!(
                std::ptr::from_ref(&**prepared) as usize,
                shared.original_payload,
                "NATIVE_PAGE_OWNER: native apply must own a distinct decoded command"
            );
            let mut base = shared.base;
            base.apply_page = entries.capacity()
                * std::mem::size_of::<Entry<ConfigRaftTypeConfig>>()
                + super::command_heap(prepared);
            assert_eq!(shared.native_calls.fetch_add(1, Ordering::SeqCst), 0);
            ACTIVE.with(|slot| {
                assert!(slot.borrow_mut().replace(Arc::clone(&shared)).is_none());
            });
            Some(Self {
                shared,
                guard: Some(ObservationGuard::start(base)),
            })
        }
    }

    impl Drop for NativeApply {
        fn drop(&mut self) {
            let result = self
                .guard
                .take()
                .expect("native observation guard")
                .finish();
            *self.shared.result.lock().expect("native ledger result") = Some(result);
            ACTIVE.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
}

pub(crate) fn command_heap(command: &AuditedConfigCommand) -> usize {
    let AuditedConfigEffect::BoundedAppend { commit, .. } = &command.effect else {
        panic!("bounded append fixture");
    };
    // Distinct Arc payloads and owned Vec/String capacities, each counted once.
    // Small Arc headers/reservation bookkeeping are omitted from this lower bound.
    size_of::<AuditedMutationFields>()
        + size_of::<PreparedConfigCommit>()
        + commit.record.encrypted_blob.capacity()
        + commit.record.plaintext_digest.capacity()
        + commit.record.principal.capacity()
        + commit.audit.capacity() * size_of::<crate::AuditRecord>()
        + commit
            .audit
            .iter()
            .map(|entry| {
                entry.yang_path.capacity()
                    + entry.previous_value.as_ref().map_or(0, String::capacity)
                    + entry.new_value.as_ref().map_or(0, String::capacity)
            })
            .sum::<usize>()
}

fn event(number: u64, principal: &str) -> crate::ManagementAuditEventRecord {
    let mut request = [0x95; 16];
    request[..8].copy_from_slice(&number.to_be_bytes());
    crate::ManagementAuditEventRecord::try_new(
        request,
        crate::ManagementAuditInstant::try_new(
            100,
            999_999_999,
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
        ["/fixture:configuration"],
        Some("synthetic-allocation-control"),
    )
    .expect("synthetic event")
}

fn mutation_event(number: u64, principal: &str, tx_id: TxId) -> crate::ManagementAuditEventRecord {
    let mut request = [0x95; 16];
    request[..8].copy_from_slice(&number.to_be_bytes());
    crate::ManagementAuditEventRecord::try_new(
        request,
        crate::ManagementAuditInstant::try_new(
            100,
            999_999_999,
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
        ["/fixture:configuration"],
        Some(tx_id.to_string()),
    )
    .expect("actual optional transaction projection for an Intent")
}

fn retained_prefix(
    identity: ConfigConsensusIdentity,
    key: &AuditKey,
    privacy: &AuditPrivacyKey,
    continuity: bool,
    expanded: bool,
) -> LedgerState {
    let mut ledger = LedgerState::new(
        identity,
        privacy
            .project(AuditPrivacyPurpose::KeyIdentity, &[])
            .expect("projection identity"),
        AuditLedgerLimits::new(4096, 1024).expect("unchanged ledger limits"),
    );
    let keys = continuity.then(|| continuity_keys(expanded));
    if keys.is_some() {
        ledger.continuity = Some(ContinuityState::new(initial_epoch(expanded)));
    }
    // Finite component setup before the core starts. Every historical operation
    // follows real authenticated admission, rejection and terminal transitions.
    // The final operation below is publicly prepared, admitted and submitted.
    for number in 0..1023_u64 {
        let principal =
            "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0";
        let tx_id = TxId::from_uuid(uuid::Uuid::from_u128(0x10000 + u128::from(number)));
        let historical = if expanded {
            // Same public event constructor and exact Confirm effect used by
            // prepare_audited_confirmation; no fabricated handle or signature.
            mutation_event(number, principal, tx_id)
        } else {
            event(number, principal)
        };
        let projected =
            ProjectedAuditEvent::project(privacy, &historical).expect("real projection");
        let mutation = expanded.then(|| {
            AuditedConfigEffect::Confirm { tx_id }
                .digest(key)
                .expect("real immutable confirmation effect digest")
        });
        let canonical = mutation.as_ref().unwrap_or(&[0x96; 32]);
        let binding = AuditOperationBinding::project(privacy, &projected, 0, canonical)
            .expect("real binding");
        let mut nonce = [0x95; 16];
        nonce[..8].copy_from_slice(&number.to_be_bytes());
        if expanded {
            nonce = *uuid::Uuid::new_v4().as_bytes();
        }
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity,
                binding,
                event: projected,
                issued_at: 100,
                expires_at: 160,
                nonce,
                key_epoch: key.epoch(),
                mutation,
            },
            key,
        )
        .expect("authenticated historical operation");
        ledger.admit(key, &handle, 100).expect("historical Intent");
        ledger
            .seal_continuity(keys.as_ref())
            .expect("sign actual Intent");
        ledger
            .resolve(key, &handle, AuditOperationState::Rejected)
            .expect("historical rejection");
        ledger
            .seal_continuity(keys.as_ref())
            .expect("sign actual rejection");
        ledger
            .acknowledge_terminal(key, &handle)
            .expect("historical terminal");
        ledger
            .seal_continuity(keys.as_ref())
            .expect("sign actual terminal");
        if expanded {
            // A rejected mutation still creates mandatory checkpoint debt.
            // Supply the real signed terminal checkpoint before the next
            // admission, exactly as native Checkpoint applies it.
            let checkpoint = signed_tail(&ledger, keys.as_ref().expect("signing keys"));
            checkpoint
                .verify(keys.as_ref().expect("keys"), identity)
                .expect("authenticated checkpoint");
            ledger
                .matches_checkpoint(&checkpoint)
                .expect("exact terminal prefix");
            ledger.continuity.as_mut().expect("continuity").checkpoint = Some(checkpoint);
        }
    }
    if expanded {
        let keys = keys.as_ref().expect("eight real signing epochs");
        for next in (initial_epoch(true) + 1)..=CONTINUITY_EPOCH {
            let chain = ledger.continuity.as_ref().expect("continuity");
            let transition = AuditKeyTransition::prepare(
                keys,
                identity,
                ledger.sequence,
                chain.terminal,
                chain.active_epoch,
                next,
            )
            .expect("cross-authenticated exact next epoch");
            ledger
                .transition_key(key, keys, &transition)
                .expect("real key transition");
        }
        assert_eq!(keys.epochs().count(), 8);
    }
    ledger
        .validate(key, identity)
        .expect("full authenticated prefix validation");
    ledger
        .validate_continuity(keys.as_ref())
        .expect("full retained signing validation");
    assert_eq!(
        (ledger.operations.len(), ledger.entries.len()),
        (1023, 3069 + transition_rows(expanded))
    );
    ledger
}

fn signed_tail(ledger: &LedgerState, keys: &AuditKeyRing) -> AuditCheckpoint {
    let chain = ledger.continuity.as_ref().expect("signed state");
    AuditCheckpoint::issue(
        keys,
        CheckpointBody {
            version: 1,
            identity: ledger.identity,
            sequence: ledger.sequence,
            root_anchor: ledger.terminal,
            anchor: chain.terminal,
            epoch_at_sequence: chain.active_epoch,
            signing_epoch: chain.active_epoch,
            acknowledged_export: [0; 32],
        },
    )
    .expect("real signed exact prefix checkpoint")
}

fn applied(admission: AuditAdmission) -> AuditOperationReceipt {
    match admission {
        AuditAdmission::Applied(receipt) => receipt,
        other => panic!("expected real durable receipt: {other:?}"),
    }
}

async fn ready(store: &ConsensusConfigStore) {
    assert_eq!(store.capacity_profile(), ConfigCapacityProfile::BoundedV1);
    store
        .initialize_cluster()
        .await
        .expect("initialize singleton");
    let deadline = tokio::time::Instant::now() + store.inner.operation_timeout;
    store
        .wait_for_known_leader(deadline)
        .await
        .expect("natural leadership");
    assert!(matches!(
        store.local_read_barrier(deadline).await,
        ReadBarrierReply::Ready(_)
    ));
}

async fn public_audited_ledger_lifetime(continuity: bool, expanded: bool) {
    public_audited_ledger_lifetime_with_transferred_owners(continuity, expanded, false).await;
}

async fn public_audited_ledger_lifetime_with_transferred_owners(
    continuity: bool,
    expanded: bool,
    transferred_owners: bool,
) {
    public_audited_ledger_lifetime_with_native_owners(
        continuity,
        expanded,
        transferred_owners,
        None,
    )
    .await;
}

#[derive(Clone, Copy, Debug)]
enum NativeOwnerCheck {
    EffectBorrow,
    CheckpointLedger,
    AttemptEncoding,
}

async fn public_audited_ledger_lifetime_with_native_owners(
    continuity: bool,
    expanded: bool,
    transferred_owners: bool,
    native_check: Option<NativeOwnerCheck>,
) {
    assert!(native_check.is_none() || transferred_owners);
    assert!(!expanded || continuity);
    assert!(!transferred_owners || expanded);
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit disk scratch root");
    let root = tempfile::Builder::new()
        .prefix("config-capacity-caller-")
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
    let topology = if expanded {
        let node = ConsensusNodeId::new(1).expect("synthetic singleton");
        let identity = ConfigConsensusIdentity::new(
            crate::ConfigConsensusClusterId::from_bytes([0xFE; 32]),
            crate::ConfigConsensusConfigurationId::from_bytes([0xFD; 32]),
            crate::ConfigConsensusConfigurationEpoch::new(i64::MAX as u64)
                .expect("largest durable configuration epoch"),
        );
        ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node]))
            .expect("maximum-width synthetic identity")
    } else {
        topology()
    };
    let identity = topology.identity();
    let external = continuity.then(|| Arc::new(ExternalCheckpointFixture::new(identity, expanded)));
    let key = AuditKey::new([0x93; 32]).expect("synthetic key");
    let privacy = AuditPrivacyKey::new([0x94; 32]).expect("synthetic privacy key");
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
    let backend = SqliteBackend::provision_config_authority(options.clone(), key.clone())
        .await
        .expect("real retained authority");
    let mut prefix = retained_prefix(identity, &key, &privacy, continuity, expanded);
    if let Some(external) = &external {
        checkpoint_retained_prefix(&mut prefix, external).await;
    }
    let setup_key = key.clone();
    crate::consensus::run_backend_sqlite_with_timeout(
        &backend,
        DURABLE_CONSENSUS_OPERATION_TIMEOUT,
        move |conn, cancellation| {
            cancellation.check_io()?;
            crate::consensus::audit::write_sync(conn, &setup_key, identity, Some(prefix), false)
        },
    )
    .await
    .expect("canonical authenticated component preseed before core open");
    let store = open_fixture(
        topology.clone(),
        backend,
        root.join("snapshots"),
        external.as_ref(),
    )
    .await;
    ready(&store).await;
    store
        .initialize_audit_authority(
            &privacy,
            AuditLedgerLimits::new(4096, 1024).expect("original limits"),
        )
        .await
        .expect("public authority initialization agrees with retained prefix");

    let reservation = store
        .try_reserve_config_preparation()
        .expect("public destination admission")
        .expect("bounded reservation before input allocation");
    let tx_id = TxId::from_uuid(uuid::Uuid::from_u128(0x9800));
    let committed_at: Timestamp = "1970-01-01T00:01:40Z"
        .parse()
        .expect("synthetic record time");
    let principal_prefix =
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/";
    let principal = format!(
        "{principal_prefix}{}",
        "p".repeat(16_384 - principal_prefix.len())
    );
    let schema_digest = SchemaDigest::from_bytes([0x99; 32]);
    let key_id = KeyId::new("k".repeat(512)).expect("maximum key ID");
    let provider = MemoryKeyProvider::new();
    provider
        .insert_active_key(
            key_id.clone(),
            KeyPurpose::Config,
            TenantId::from_static("test"),
            Zeroizing::new([0x9A; 32]),
        )
        .expect("synthetic provider");
    let make_aad = |name: &str| {
        EnvelopeAad::config(
            TenantId::from_static("test"),
            1,
            ConfigAad::new(tx_id, None, committed_at, &principal, schema_digest, name)
                .expect("real bound metadata"),
        )
    };
    let mut name = String::from("synthetic-\"\\é-");
    let initial = opc_key::serialize_bound_aad(&make_aad(&name), &key_id)
        .expect("base AAD")
        .len();
    name.extend(std::iter::repeat_n('s', 65_536 - initial));
    let aad = make_aad(&name);
    assert_eq!(
        opc_key::serialize_bound_aad(&aad, &key_id)
            .expect("maximum AAD")
            .len(),
        65_536
    );
    let mut plaintext = b"\x89OPCCFG\x02\r\n\x1a\n{\"config\":\"".to_vec();
    plaintext.extend(std::iter::repeat_n(b'x', 1_572_864 - 2));
    plaintext.extend_from_slice(b"\",\"source\":null,\"idempotency_key\":\"");
    plaintext.resize(1_572_864 + 65_536 - 2, b'r');
    plaintext.extend_from_slice(b"\"}");
    assert_eq!(plaintext.len(), 1_638_400);
    let envelope = opc_crypto::encrypt_reserved_bounded_config_envelope(
        reservation,
        &provider,
        &aad,
        &plaintext,
    )
    .await
    .expect("real at-limit encryption with destination reservation");
    let mut encrypted_blob = envelope.encoded().to_vec();
    // The expanded case transfers 14.5 MiB: close to the existing command-owner
    // guard, which refuses 15 MiB before any Intent can be admitted. Both the
    // reserved backing and eventual prepared owner are measured concretely.
    let transferred_capacity = 14 * 1024 * 1024 + usize::from(expanded) * 512 * 1024;
    if !transferred_owners {
        encrypted_blob.reserve_exact(transferred_capacity - encrypted_blob.len());
        assert!(encrypted_blob.capacity() >= transferred_capacity);
    } else {
        assert_eq!(encrypted_blob.capacity(), encrypted_blob.len());
    }
    let mut record = CommitRecord {
        tx_id,
        parent_tx_id: None,
        version: ConfigVersion::new(1),
        committed_at,
        principal,
        source: crate::CommitSource::Gnmi,
        schema_digest,
        plaintext_digest: Sha256::digest(&plaintext).to_vec(),
        encrypted_blob,
        rollback_point: false,
        confirmed_deadline: None,
    };
    let mut audit: Vec<crate::AuditRecord> = (0..22)
        .map(|sequence| crate::AuditRecord {
            tx_id,
            sequence,
            yang_path: format!(
                "/fixture:{}",
                "x".repeat(if sequence == 21 { 128 } else { 8192 } - 9)
            ),
            op_type: crate::types::AuditOpType::Update,
            previous_value: Some("synthetic-before".to_owned()),
            new_value: Some("synthetic-after".to_owned()),
            redaction_applied: false,
            previous_hash: [0; 32],
            entry_hmac: [0; 32],
        })
        .collect();
    if transferred_owners {
        // Redistribute exactly the existing ciphertext case's spare backing.
        // No logical bytes, audit entries or admission formula are changed.
        let spare = transferred_capacity - record.encrypted_blob.capacity();
        let principal_capacity = record.principal.capacity();
        let digest_capacity = record.plaintext_digest.capacity();
        let audit_capacity = audit.capacity();
        let principal_extra = spare / 3;
        let audit_extra = (spare / 3) / size_of::<crate::AuditRecord>();
        let digest_extra = spare - principal_extra - audit_extra * size_of::<crate::AuditRecord>();
        record
            .principal
            .reserve_exact(principal_capacity + principal_extra - record.principal.len());
        record
            .plaintext_digest
            .reserve_exact(digest_capacity + digest_extra - record.plaintext_digest.len());
        audit.reserve_exact(audit_capacity + audit_extra - audit.len());
        assert_eq!(
            record.principal.capacity(),
            principal_capacity + principal_extra
        );
        assert_eq!(
            record.plaintext_digest.capacity(),
            digest_capacity + digest_extra
        );
        assert_eq!(audit.capacity(), audit_capacity + audit_extra);
        assert_eq!(record.principal.len(), 16_384);
        assert_eq!(record.plaintext_digest.len(), 32);
        assert_eq!(audit.len(), 22);
        assert_eq!(
            record.principal.capacity() - principal_capacity + record.plaintext_digest.capacity()
                - digest_capacity
                + (audit.capacity() - audit_capacity) * size_of::<crate::AuditRecord>(),
            spare,
            "real transferred allocations exactly replace the old ciphertext spare capacity"
        );
    }
    let transferred_observation = transferred_owners.then(|| {
        crate::consensus::capacity_record::transferred_owner_observation::Registration::new(
            &record,
            &audit,
            envelope.encoded(),
        )
    });
    // The retained record's canonical principal metadata and the management
    // caller projection have independent size contracts; keep both valid.
    let caller_principal =
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0";
    let event = if expanded {
        mutation_event(1023, caller_principal, tx_id)
    } else {
        event(1023, caller_principal)
    };
    let caller = AuditCaller::project(&privacy, "test", caller_principal).expect("trusted caller");
    let normalization =
        crate::consensus::capacity_record::normalization_observation::Registration::new(
            &record,
            envelope.encoded(),
        );
    let attested =
        AttestedConfigCommit::try_new(record, audit, envelope.claim().expect("original claim"))
            .expect("exact plaintext attestation");
    let evidence = attested.capacity_evidence().expect("genuine size evidence");
    assert_eq!(
        (evidence.logical_bytes(), evidence.replay_bytes()),
        (1_572_864, 65_536)
    );
    let prepared = store
        .prepare_audited_commit(&privacy, &event, attested, Duration::from_secs(60))
        .expect("public bounded audited preparation admits real spare capacity");
    let handle = prepared.handle().clone();
    let request = derive_durable_request_id(identity, b"audit-config", &handle.mac);
    let probe = ConfigConsensusCommandSizeProbe {
        schema_version: 8,
        identity,
        request_id: request,
        logical_time: maximum_encoded_config_timestamp().expect("real preflight time"),
        intent: &ConfigMutationIntent::AuditedMutation(prepared.command().clone()),
    };
    let metadata =
        config_command_encoded_size(&probe).expect("real command size") - envelope.encoded().len();
    assert!((METADATA_BYTES - 8192..=METADATA_BYTES).contains(&metadata));
    let native_owners = if native_check.is_some() {
        Some(
            crate::consensus::store::config_capacity_native_owner_observation::Registration::new(
                &store.inner.backend,
                request,
            )
            .await,
        )
    } else {
        None
    };
    let admitted = applied(store.admit_audit_operation_local(&handle, caller).await);
    assert_eq!(admitted.state(), AuditOperationState::Intent);
    let recovery = prepared.encode().expect("real original recovery encoding");
    let base = Sample {
        command: command_heap(prepared.command()),
        encryption_alias: envelope.encoded().len(),
        recovery: recovery.capacity(),
        ..Sample::default()
    };
    #[cfg(feature = "dangerous-test-hooks")]
    let bridge_census = Arc::new(crate::config_capacity_observation::PreparationCensus::default());
    #[cfg(feature = "dangerous-test-hooks")]
    let bridge_preparation_owner = bridge_census
        .observe_audited(store.status().node_id, &prepared)
        .expect("borrow one genuine native preparation for the callback regression");
    #[cfg(feature = "dangerous-test-hooks")]
    let bridge_oracles = Arc::new(BridgeOracles {
        census: bridge_census.clone(),
        result: std::sync::Mutex::new((0, 0, 0)),
        derived: std::sync::Mutex::new(DerivedBridgeOracle::default()),
    });
    #[cfg(feature = "dangerous-test-hooks")]
    let bridge_registration = store
        .observe_capacity_native_owners_for_test(
            &prepared,
            bridge_census.clone(),
            bridge_oracles.clone(),
        )
        .await
        .expect("attach actual owner oracle comparison");
    let observation = observation::Registration::new(
        request,
        base,
        prepared.command(),
        3070 + transition_rows(expanded),
    );
    let receipt = applied(
        store
            .submit_audited_mutation_local(&prepared, &admitted, caller)
            .await,
    );
    assert_eq!(
        receipt.state(),
        AuditOperationState::Committed { version: 1 }
    );
    if let Some(external) = &external {
        assert_eq!(
            external
                .load(identity)
                .await
                .expect("effect checkpoint")
                .expect("required Intent checkpoint")
                .sequence(),
            3070 + transition_rows(expanded) as u64,
            "CONTINUITY_ADMITTED: native effect required the exact checkpointed Intent"
        );
    }
    let terminal = applied(store.finish_audit_operation(&handle, caller).await);
    assert!(terminal.terminal_recorded());
    assert_eq!(terminal.state(), receipt.state());
    if let Some(external) = &external {
        store
            .complete_required_audit_outcome(&terminal, caller)
            .await
            .expect("mandatory terminal and independent checkpoint completion");
        verify_continuity(&store, external).await;
    }
    verify(&store, &provider, &aad, &plaintext, &prepared, caller).await;
    store.shutdown().await.expect("join native owners");
    #[cfg(feature = "dangerous-test-hooks")]
    bridge_registration.detach();
    if let Some(native_owners) = &native_owners {
        native_owners.detach();
    }
    drop(store);
    assert_eq!(
        SqliteBackend::reopen_config_authority(options.clone(), key.clone())
            .await
            .err(),
        Some(crate::RetainedConfigError::InUse),
        "the original prepared command and envelope alias still own this bounded engine"
    );
    // Preserve witnesses from the actual owners after the complete measured
    // native lifecycle. Protected recovery bytes and the original handle are
    // sufficient for read-only verification after those owners retire.
    let (
        original_alias_matches,
        original_ciphertext_capacity,
        original_ciphertext_len,
        original_transferred_capacities,
        original_transferred_lengths,
    ) = {
        let AuditedConfigEffect::BoundedAppend { commit, .. } = &prepared.command().effect else {
            panic!("bounded effect");
        };
        (
            envelope.encoded() == commit.record.encrypted_blob,
            commit.record.encrypted_blob.capacity(),
            commit.record.encrypted_blob.len(),
            [
                commit.record.principal.capacity(),
                commit.record.plaintext_digest.capacity(),
                commit.audit.capacity() * size_of::<crate::AuditRecord>(),
            ],
            [
                commit.record.principal.len(),
                commit.record.plaintext_digest.len(),
                commit.audit.len() * size_of::<crate::AuditRecord>(),
            ],
        )
    };
    #[cfg(feature = "dangerous-test-hooks")]
    drop(bridge_preparation_owner);
    drop(prepared);
    drop(envelope);
    let backend = SqliteBackend::reopen_config_authority(options, key)
        .await
        .expect("full original retained authority validation after actual owner retirement");
    let reopened = open_fixture(topology, backend, root.join("snapshots"), external.as_ref()).await;
    ready(&reopened).await;
    let recovered = PreparedAuditedMutation::decode(&recovery)
        .expect("decode the original protected recovery bytes for read-only verification");
    assert_eq!(
        recovered.handle(),
        &handle,
        "retain the exact original handle"
    );
    verify(&reopened, &provider, &aad, &plaintext, &recovered, caller).await;
    if let Some(external) = &external {
        verify_continuity(&reopened, external).await;
    }
    reopened.shutdown().await.expect("join reopened owners");
    #[cfg(feature = "dangerous-test-hooks")]
    {
        let result = *bridge_oracles.result.lock().unwrap();
        let drained = bridge_registration.snapshot();
        let preparation_drain = bridge_census.snapshot();
        let derived = *bridge_oracles.derived.lock().unwrap();
        println!("CONFIG_CAPACITY_NATIVE_DERIVED_LIFECYCLE observed={derived:?} exact_readback=true original_recovery=true retained_reopen=true joined_shutdown=true full_memory_bound=false");
        assert_eq!(
            derived.callbacks, 1,
            "CONFIG_CAPACITY_NATIVE_DERIVED_CHECKPOINT_RED: observe the original derived Vec before validate returns"
        );
        assert!(derived.capacity_bytes > 0);
        assert_eq!(derived.matched_oracles, 1);
        assert_eq!(
            derived.selected_bytes, derived.expected_selected_bytes,
            "CONFIG_CAPACITY_NATIVE_DERIVED_BYTES_RED: charge the live validation Vec capacity"
        );
        assert_eq!(
            derived.node_bytes, derived.expected_node_bytes,
            "CONFIG_CAPACITY_NATIVE_DERIVED_NODE_RED: the same live allocation belongs to this node"
        );
        println!("CONFIG_CAPACITY_NATIVE_BRIDGE_ORACLES_LIFECYCLE exact_readback=true original_recovery=true retained_reopen=true compared={} matched={}", result.0, result.1);
        assert_eq!((result.0, result.1), (3, 3), "CONFIG_CAPACITY_NATIVE_BRIDGE_ORACLE_RED: actual command_heap and ledger_heap capacities");
        println!("CONFIG_CAPACITY_NATIVE_COUNTER_READ_LIFECYCLE reads={} preparation_drain={preparation_drain:?} original_recovery=true retained_reopen=true joined_shutdown=true", result.2);
        assert_eq!(result.2, 3, "CONFIG_CAPACITY_NATIVE_COUNTER_READ_RED: metadata callback reads the same current census at every real native checkpoint");
        assert_eq!(preparation_drain, Default::default());
        assert!(!drained.registered);
        assert_eq!(drained.native_scopes, 0);
        assert_eq!(drained.transport_scopes, 0);
    }
    if expanded {
        println!("CONFIG_CAPACITY_LEDGER_CLOSURE_LIFECYCLE exact_readback=true original_recovery=true retained_reopen=true mandatory_checkpoint=true");
    }
    if transferred_owners {
        println!("CONFIG_CAPACITY_TRANSFERRED_OWNERS_LIFECYCLE exact_readback=true original_recovery=true retained_reopen=true mandatory_checkpoint=true");
    }
    if let Some(native_owners) = native_owners {
        let owners = native_owners.finish();
        println!("CONFIG_CAPACITY_NATIVE_OWNERS_LIFECYCLE check={native_check:?} exact_readback=true original_recovery=true retained_reopen=true mandatory_checkpoint=true owners={owners:?}");
        assert_eq!(owners.effects.len(), 1, "NATIVE_OWNERS_EFFECT_OBSERVED");
        let effect = owners.effects[0];
        assert!(
            effect.same_ciphertext_digest,
            "actual consumed ciphertext matches native source"
        );
        assert!(effect.native_commit_bytes > 0 && effect.consumed_commit_bytes > 0);
        assert_eq!(
            owners.checkpoints.len(),
            2,
            "NATIVE_OWNERS_CHECKPOINTS_OBSERVED"
        );
        for (checkpoint, expected) in owners.checkpoints.iter().zip([3077_u64, 3079]) {
            assert_eq!(checkpoint.sequence, expected);
            assert!(
                checkpoint.page_bytes > 0,
                "actual decoded native checkpoint page"
            );
            for kind in 0..2 {
                for state in [checkpoint.at_submit[kind], checkpoint.at_native[kind]] {
                    assert!(state.created > 0 && state.last_capacity > 0);
                    assert!(state.dropped <= state.created);
                    assert_eq!(state.live == 0, state.created == state.dropped);
                }
            }
        }
        match native_check.expect("selected ownership contract") {
            NativeOwnerCheck::EffectBorrow => {
                assert!(effect.same_record && effect.same_ciphertext && effect.extra_commit_bytes == 0,
                    "NATIVE_EFFECT_BORROW: actual append input must borrow the native record/ciphertext; {effect:?}");
            }
            NativeOwnerCheck::CheckpointLedger => {
                for checkpoint in &owners.checkpoints {
                    assert!(checkpoint.at_submit[0].live == 0 && checkpoint.at_native[0].live == 0,
                        "NATIVE_CHECKPOINT_LEDGER_RELEASE: actual caller ledger must end before native submission; {checkpoint:?}");
                }
            }
            NativeOwnerCheck::AttemptEncoding => {
                for checkpoint in &owners.checkpoints {
                    assert!(checkpoint.at_submit[1].live == 0 && checkpoint.at_native[1].live == 0,
                        "NATIVE_ATTEMPT_ENCODING_RELEASE: actual request-identity JSON must end before native submission; {checkpoint:?}");
                }
            }
        }
    }
    let measured = observation.finish();
    // The complete real native lifecycle, exact readback, original recovery and
    // retained reopen above must finish before a growth control can fail here.
    assert_eq!(
        measured.mutation_owners, 1,
        "one real native mutable ledger"
    );
    let initial = measured.mutation_initial.expect("native decoded ledger");
    let final_collections = measured.mutation_final.expect("native mutated ledger");
    let before_entries = 3070 + transition_rows(expanded);
    assert_eq!(
        initial.lengths,
        [
            before_entries,
            1024,
            if continuity { before_entries } else { 0 }
        ],
        "LEDGER_GROWTH_NATIVE_PREFIX: actual admitted prefix"
    );
    assert_eq!(
        initial.capacities, initial.lengths,
        "LEDGER_GROWTH_NATIVE_EXACT_DECODE: real decoded collection capacities"
    );
    assert_eq!(
        final_collections.lengths,
        [
            before_entries + 1,
            1024,
            if continuity { before_entries + 1 } else { 0 },
        ],
        "LEDGER_GROWTH_NATIVE_OUTCOME: one real authoritative outcome"
    );
    println!(
        "CONFIG_CAPACITY_LEDGER_GROWTH_NATIVE initial={initial:?} final={final_collections:?} exact_readback=true original_recovery=true retained_reopen=true"
    );
    assert_eq!(
        final_collections.capacities[0], final_collections.lengths[0],
        "LEDGER_GROWTH_NATIVE_ENTRIES: append must reserve its actual next element"
    );
    assert_eq!(
        final_collections.capacities[1], final_collections.lengths[1],
        "LEDGER_GROWTH_NATIVE_OPERATIONS: retained operations do not grow on outcome"
    );
    assert_eq!(
        final_collections.capacities[2], final_collections.lengths[2],
        "LEDGER_GROWTH_NATIVE_ROWS: sealing must reserve its actual missing rows"
    );
    // The original owners survived measured apply, readback, recovery, and
    // shutdown; their live witnesses were captured before explicit retirement.
    // Test-only plaintext/decryption witnesses are outside the production inventory.
    assert!(!recovery.is_empty());
    assert!(original_alias_matches, "exact original envelope alias");
    // The original transferred spare-capacity owner was asserted above.
    // Count the actual prepared capacity, including any real normalization.
    assert!(original_ciphertext_capacity >= original_ciphertext_len);
    assert!(measured.apply_reads >= 2 && measured.writes == 1);
    assert_eq!(measured.derived_len, 1024);
    assert!(
        measured.peak.apply_page > 0
            && measured.peak.decoded_ledger > 0
            && (measured.peak.row_json > 0 || measured.peak.write_json > 0)
    );
    assert!(measured.validation_peak.derived > 0 && measured.validation_peak.authentication > 0);
    if continuity {
        assert_eq!(
            measured.continuity_rows,
            3071 + transition_rows(expanded),
            "CONTINUITY_ROWS: the measured native read includes the real committed signature"
        );
        assert!(
            measured.continuity_bytes
                >= (3071 + transition_rows(expanded)) * size_of::<SignedAuditRow>()
        );
        assert!(measured.continuity_checks > 0);
        assert!(
            measured.read_continuity_peak.decoded_ledger > 0
                && measured.read_continuity_peak.authentication > 0,
            "READ_CONTINUITY_OWNER: actual decoded ledger remains live during signing verification"
        );
        assert!(measured.mutation_continuity_peak.held_ledger > 0
            && measured.mutation_continuity_peak.authentication > 0,
            "MUTATION_CONTINUITY_OWNER: actual held ledger remains live during post-effect signing verification");
        assert_eq!(measured.encoding_calls, 1);
        assert!(measured.encoding_peak.decoded_ledger > 0 && measured.encoding_peak.write_json > 0,
            "ENCODING_LEDGER_OWNER: real decoded ledger overlaps the allocated row during serialization");
        assert!(measured.continuity_peak.authentication > 0);
        assert!(measured.continuity_peak.decoded_ledger + measured.continuity_peak.held_ledger > 0);
        assert!(
            measured.mutation_peak.held_ledger > 0 && measured.mutation_peak.authentication > 0
        );
        assert!(measured.encoding_peak.decoded_ledger > 0 && measured.encoding_peak.write_json > 0);
        assert_eq!(
            measured.peak.caller_ledger, 0,
            "PRIOR_CALLER_DROP: the previous repair remains active"
        );
        if transferred_owners {
            println!("CONFIG_CAPACITY_TRANSFERRED_OWNERS metadata={metadata} retained_rows=3079 signing_epochs=8 measured={measured:?}");
            assert!(measured.peak.total <= OPERATION_BYTES,
                "CONFIG_CAPACITY_TRANSFERRED_OWNERS_BOUND: real principal/digest/audit backing and native owners exceed 32 MiB: {:?}", measured.peak);
        } else if expanded {
            println!("CONFIG_CAPACITY_LEDGER_CLOSURE metadata={metadata} retained_rows=3079 signing_epochs=8 exact_readback=true original_recovery=true retained_reopen=true mandatory_checkpoint=true measured={measured:?}");
            assert!(measured.peak.total <= OPERATION_BYTES,
                "CONFIG_CAPACITY_LEDGER_CLOSURE_BOUND: actual reachable retained ledger/native owners exceed 32 MiB: {:?}", measured.peak);
        } else {
            println!("CONFIG_CAPACITY_PUBLIC_CONTINUITY metadata={metadata} exact_readback=true original_recovery=true retained_reopen=true mandatory_checkpoint=true measured={measured:?}");
            assert!(measured.peak.total <= OPERATION_BYTES,
            "CONFIG_CAPACITY_PUBLIC_CONTINUITY_BOUND: real signed retained state and native apply payloads exceed 32 MiB: {:?}", measured.peak);
        }
    } else {
        assert_eq!(measured.continuity_rows, 0);
        println!("CONFIG_CAPACITY_PUBLIC_CALLER_LEDGER metadata={metadata} exact_readback=true original_recovery=true retained_reopen=true measured={measured:?}");
        assert!(measured.peak.total <= OPERATION_BYTES,
            "CONFIG_CAPACITY_PUBLIC_CALLER_LEDGER_BOUND: real public caller and native apply payloads exceed 32 MiB: {:?}", measured.peak);
    }
    // Check the actual copy overlap after the full lifecycle as well. Baseline
    // and removal controls must fail at the native bound above, not this gate.
    let normalization = normalization.finish();
    if expanded && !transferred_owners {
        assert!(
            normalization.is_some(),
            "real reserved normalization observed"
        );
    }
    if let Some(normalized) = normalization.filter(|_| !transferred_owners) {
        assert!(
            normalized.has_reservation && normalized.same_bytes && normalized.old_owner_released
        );
        assert!(normalized.alias_bytes > 0 && normalized.other_owned > 0);
        assert_eq!(normalized.old_capacity, transferred_capacity);
        assert!(normalized.new_capacity > 0 && normalized.new_capacity < normalized.old_capacity);
        assert_eq!(normalized.post_capacity, original_ciphertext_capacity);
        println!("CONFIG_CAPACITY_NORMALIZATION owners={normalized:?}");
        assert!(
            normalized.total <= OPERATION_BYTES,
            "CONFIG_CAPACITY_NORMALIZATION_BOUND: real old/new/alias payloads exceed 32 MiB"
        );
    }
    if let Some(observation) = transferred_observation {
        let normalized = observation.finish();
        assert!(normalized.has_reservation && normalized.copy_observed);
        assert_eq!(normalized.released, [true; 3]);
        assert_eq!(normalized.post_capacities, original_transferred_capacities,);
        assert_eq!(normalized.post_capacities, original_transferred_lengths);
        assert!(normalized.alias_bytes > 0 && normalized.nested_bytes > 0);
        println!("CONFIG_CAPACITY_TRANSFERRED_OWNERS_NORMALIZATION owners={normalized:?}");
        assert!(
            normalized.total <= OPERATION_BYTES,
            "CONFIG_CAPACITY_TRANSFERRED_OWNERS_COPY_BOUND: old/new/alias owners exceed 32 MiB"
        );
    }
}

#[tokio::test]
async fn config_capacity_957_public_audited_caller_ledger_lifetime() {
    public_audited_ledger_lifetime(false, false).await;
}

#[tokio::test]
async fn config_capacity_957_public_audited_continuity_row_lifetime() {
    public_audited_ledger_lifetime(true, false).await;
}

#[tokio::test]
async fn config_capacity_957_public_audited_ledger_owner_closure() {
    public_audited_ledger_lifetime(true, true).await;
}

#[tokio::test]
async fn config_capacity_957_public_audited_transferred_owner_closure() {
    public_audited_ledger_lifetime_with_transferred_owners(true, true, true).await;
}

#[tokio::test]
async fn config_capacity_957_public_audited_native_effect_borrow() {
    public_audited_ledger_lifetime_with_native_owners(
        true,
        true,
        true,
        Some(NativeOwnerCheck::EffectBorrow),
    )
    .await;
}

#[tokio::test]
async fn config_capacity_957_public_audited_checkpoint_ledger_release() {
    public_audited_ledger_lifetime_with_native_owners(
        true,
        true,
        true,
        Some(NativeOwnerCheck::CheckpointLedger),
    )
    .await;
}

#[tokio::test]
async fn config_capacity_957_public_audited_attempt_encoding_release() {
    public_audited_ledger_lifetime_with_native_owners(
        true,
        true,
        true,
        Some(NativeOwnerCheck::AttemptEncoding),
    )
    .await;
}

async fn verify(
    store: &ConsensusConfigStore,
    provider: &MemoryKeyProvider,
    aad: &EnvelopeAad,
    plaintext: &[u8],
    prepared: &PreparedAuditedMutation,
    caller: AuditCaller,
) {
    let AuditedConfigEffect::BoundedAppend { commit, .. } = &prepared.command().effect else {
        panic!("bounded effect");
    };
    let before = store.inner.raft.metrics().borrow().last_log_index;
    let actual = store
        .load_latest()
        .await
        .expect("real native readback")
        .expect("committed head");
    assert!(actual.record == commit.record, "exact retained record");
    assert!(
        actual.audit == commit.audit,
        "exact retained audit metadata"
    );
    let decoded = opc_crypto::decrypt_envelope(provider, aad, &actual.record.encrypted_blob)
        .await
        .expect("authenticate exact encrypted record");
    assert!(
        decoded.as_slice() == plaintext,
        "exact authenticated plaintext"
    );
    let receipt = store
        .lookup_audit_operation(prepared.handle(), caller)
        .await
        .expect("authenticated original-handle recovery")
        .expect("retained original operation");
    assert_eq!(receipt.handle(), prepared.handle());
    assert_eq!(
        receipt.state(),
        AuditOperationState::Committed { version: 1 }
    );
    assert!(receipt.terminal_recorded());
    assert_eq!(
        store.inner.raft.metrics().borrow().last_log_index,
        before,
        "readback appends no proposal"
    );
}
