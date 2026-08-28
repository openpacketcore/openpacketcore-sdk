use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use crate::consensus::snapshot::{rename_exchange_in_directory, rename_noreplace_in_directory};
use hmac::Mac;
use opc_consensus::engine::LogId;
use opc_types::Timestamp;
use rusqlite::backup::Backup;
use rusqlite::types::{Value, ValueRef};
#[cfg(target_os = "linux")]
use rusqlite::OpenFlags;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    plan_mac, FinalizationPredecessorCapsule, LegacyBootstrapMembershipCapsule,
    RecoveryAuthorityProfile, RecoveryDecisionBasis, RecoveryDigest, RecoveryError,
    RecoveryExecutionState, RecoveryFixedPlacementPolicy, RecoveryIntegrityKey, RecoveryLimits,
    RecoveryPlan, RecoveryReplica, RecoveryReplicaEvidence, RecoveryReplicaFormat,
};
use crate::consensus::snapshot::{SNAPSHOT_DATABASE_MAX_BYTES, SNAPSHOT_ENVELOPE_FOOTER_BYTES};
use crate::consensus::types::{FinalizeOperatorRecoveryV2Intent, SessionMutationOutcome};
use crate::consensus::{
    SessionConsensusConfigurationEpoch, SessionConsensusConfigurationId,
    SessionConsensusEntryDigest, SessionConsensusIdentity, SessionConsensusNodeId,
    SessionConsensusRequestId, SessionMutationIntent, SESSION_CONSENSUS_SCHEMA_VERSION,
};
use crate::sqlite::{consensus, open_regular_read_nofollow, ops};
use crate::{
    ReplicationEntry, ReplicationTxId, FENCED_MUTATION_ROSTER_MAX_LIVE_ROSTERS,
    FENCED_MUTATION_ROSTER_MAX_RESERVED_AND_RETAINED, FENCED_TRANSITION_MAX_HISTORY_ENTRIES,
    FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES, FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS,
    FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES,
    FENCED_TRANSITION_V2_RECEIPT_RESPONSE_MAX_BYTES, FENCED_TRANSITION_V2_REQUEST_ID_BYTES,
    REPLICATION_TX_ID_MAX_BYTES, REPLICATION_TX_ID_MIN_BYTES,
};

const PATH_MAX_BYTES: usize = 4_096;
#[cfg(any(target_os = "linux", test))]
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_millis(100);
const SNAPSHOT_FOOTER_MAGIC: &[u8; 8] = b"OPCSNP01";
const PLAN_MAC_DOMAIN: &[u8] = b"openpacketcore/session-recovery/plan-seal/v1\0";
const WORKFLOW_MAC_DOMAIN: &[u8] = b"openpacketcore/session-recovery/workflow/v1\0";
const BACKUP_MAC_DOMAIN: &[u8] = b"openpacketcore/session-recovery/backup/v1\0";
// Version the branch domain whenever its authenticated projection changes.
// V2 commits the entire authoritative retained suffix rather than only the
// final committed row, so a plan made by an older reader cannot silently
// compare as this stronger proof.
const CURRENT_BRANCH_DOMAIN: &[u8] = b"openpacketcore/session-recovery/current-branch/v2\0";
const LEGACY_BRANCH_DOMAIN: &[u8] = b"openpacketcore/session-recovery/legacy-branch/v1\0";
const PATH_BINDING_DOMAIN: &[u8] = b"openpacketcore/session-recovery/path-binding/v1\0";
#[cfg(target_os = "linux")]
const FILE_IDENTITY_DOMAIN: &[u8] = b"openpacketcore/session-recovery/file-identity/v1\0";
const LOGICAL_STATE_DOMAIN: &[u8] = b"openpacketcore/session-recovery/logical-state/v1\0";
/// Stable projection of logical state across the one V2 finalization
/// transaction.  V2 intentionally clears `leases.active` and advances its
/// two allocators, so the ordinary logical-state digest cannot be compared to
/// its predecessor after finalization.  This projection commits every
/// unaffected state byte while the exact V2 postconditions authenticate the
/// three deliberately changed projections separately.
const RECOVERY_V2_INVARIANT_STATE_DOMAIN: &[u8] =
    b"openpacketcore/session-recovery/v2-invariant-state/v1\0";
// V2 apply has no caller-provided recovery envelope.  Keep its exact
// predecessor projection bounded by the same finite protocol capacities as
// the largest admissible recovery inspection, rather than accepting an
// unbounded transactional scan or silently depending on an operator limit
// absent from the replicated command.
const RECOVERY_V2_INVARIANT_PROTOCOL_MAX_ROWS: u64 = 10_000_000;
const RECOVERY_V2_INVARIANT_PROTOCOL_MAX_VALUE_BYTES: u64 = 16 * 1024 * 1024;
const RECOVERY_V2_INVARIANT_PROTOCOL_MAX_TOTAL_VALUE_BYTES: u64 = SNAPSHOT_DATABASE_MAX_BYTES * 8;
const FILE_DIGEST_DOMAIN: &[u8] = b"openpacketcore/session-recovery/file/v1\0";
const PROTECTED_ROSTER_LAYOUT_DOMAIN: &[u8] =
    b"openpacketcore/session-recovery/protected-roster-layout/v1\0";
const PROTECTED_ROSTER_TRUST_ROOT_DOMAIN: &[u8] =
    b"openpacketcore/session-recovery/protected-roster-trust-root/v1\0";
const PROTECTED_ROSTER_DIGEST_DOMAIN: &[u8] =
    b"openpacketcore/session-recovery/protected-roster-digest/v1\0";
const AUTHORITY_DESCRIPTOR_DOMAIN: &[u8] =
    b"openpacketcore/session-recovery/authority-descriptor/v1\0";
const WORKFLOW_VERSION: u16 = 7;
const RECOVERY_TERMINAL_PROOF_REVISION: u16 = 1;
const RECOVERY_TERMINAL_PROOF_DOMAIN: &str = "openpacketcore/session-recovery/terminal-proof/v1";
const RECOVERY_TERMINAL_OUTCOME_DOMAIN: &[u8] =
    b"openpacketcore/session-recovery/terminal-outcome/v1\0";
const MAX_SCHEMA_SQL_BYTES: usize = 16_384;

type RetainedConsensusLogEvidence = (
    Vec<LogId<SessionConsensusNodeId>>,
    Vec<
        opc_consensus::engine::StoredMembership<
            SessionConsensusNodeId,
            opc_consensus::engine::EmptyNode,
        >,
    >,
);

#[cfg(test)]
type PathOnceHook = Box<dyn FnOnce(&Path)>;
#[cfg(test)]
type PathOnceBoolHook = Box<dyn FnOnce(&Path) -> bool>;
#[cfg(test)]
type PathMutHook = Box<dyn FnMut(&Path)>;
#[cfg(test)]
type OnceHook = Box<dyn FnOnce()>;

#[cfg(test)]
std::thread_local! {
    static ATOMIC_WRITE_BEFORE_RENAME_HOOK: std::cell::RefCell<Option<PathOnceHook>> = const {
        std::cell::RefCell::new(None)
    };
    static ATOMIC_WRITE_AFTER_RENAME_HOOK: std::cell::RefCell<Option<PathOnceHook>> = const {
        std::cell::RefCell::new(None)
    };
    static ATOMIC_WRITE_AFTER_DIRECTORY_SYNC_HOOK: std::cell::RefCell<Option<PathOnceHook>> = const {
        std::cell::RefCell::new(None)
    };
    static BOUNDED_JSON_AFTER_OPEN_HOOK: std::cell::RefCell<Option<PathOnceHook>> = const {
        std::cell::RefCell::new(None)
    };
    static TARGET_BACKUP_SNAPSHOT_DIRECTORY_SYNC_HOOK: std::cell::RefCell<Option<PathOnceBoolHook>> = const {
        std::cell::RefCell::new(None)
    };
    static PROMOTION_BEFORE_RENAME_HOOK: std::cell::RefCell<Option<PathOnceHook>> = const {
        std::cell::RefCell::new(None)
    };
    static PROMOTION_BEFORE_DESTINATION_RENAME_HOOK: std::cell::RefCell<Option<PathOnceHook>> = const {
        std::cell::RefCell::new(None)
    };
    static PROMOTION_AFTER_RENAME_HOOK: std::cell::RefCell<Option<PathOnceHook>> = const {
        std::cell::RefCell::new(None)
    };
    static PROMOTION_AFTER_DIRECTORY_SYNC_HOOK: std::cell::RefCell<Option<PathOnceHook>> = const {
        std::cell::RefCell::new(None)
    };
    static FAIL_NEXT_PROMOTION_AFTER_RENAME: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static PLANNED_FLEET_INSPECTION_COUNT: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
    static PINNED_INSPECTION_BEFORE_SEMANTIC_HOOK: std::cell::RefCell<Option<PathMutHook>> = const {
        std::cell::RefCell::new(None)
    };
    static PINNED_INSPECTION_AFTER_SEMANTIC_HOOK: std::cell::RefCell<Option<PathMutHook>> = const {
        std::cell::RefCell::new(None)
    };
    static TARGET_DATABASE_AFTER_IDENTITY_ADMISSION_HOOK: std::cell::RefCell<Option<PathOnceHook>> = const {
        std::cell::RefCell::new(None)
    };
    // This seam models the narrow interval in which SQLite's bundled Unix
    // VFS has resolved a proc-descriptor pathname but has not yet opened its
    // main file.  It is intentionally test-only: production always passes
    // the proc descriptor path directly to SQLite.
    static PINNED_SQLITE_OPEN_PATH_OVERRIDE: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
    static PINNED_SQLITE_AFTER_OPEN_HOOK: std::cell::RefCell<Option<OnceHook>> = const {
        std::cell::RefCell::new(None)
    };
    static PINNED_SQLITE_SEMANTIC_OPEN_COUNT: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
    // Models a same-inode WAL writer between the former separate legacy
    // predecessor prepass and the descriptor-bound classification proof.
    static LEGACY_CLASSIFICATION_BEFORE_PROOF_HOOK: std::cell::RefCell<Option<OnceHook>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum AtomicWriteTestBoundary {
    BeforeRename,
    AfterRename,
    AfterDirectorySync,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum PromotionTestBoundary {
    BeforeRename,
    BeforeDestinationRename,
    AfterRename,
    AfterDirectorySync,
}

#[cfg(test)]
fn install_atomic_write_boundary_hook(
    boundary: AtomicWriteTestBoundary,
    hook: impl FnOnce(&Path) + 'static,
) {
    let slot = match boundary {
        AtomicWriteTestBoundary::BeforeRename => &ATOMIC_WRITE_BEFORE_RENAME_HOOK,
        AtomicWriteTestBoundary::AfterRename => &ATOMIC_WRITE_AFTER_RENAME_HOOK,
        AtomicWriteTestBoundary::AfterDirectorySync => &ATOMIC_WRITE_AFTER_DIRECTORY_SYNC_HOOK,
    };
    slot.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_atomic_write_boundary_hook(boundary: AtomicWriteTestBoundary, path: &Path) {
    let slot = match boundary {
        AtomicWriteTestBoundary::BeforeRename => &ATOMIC_WRITE_BEFORE_RENAME_HOOK,
        AtomicWriteTestBoundary::AfterRename => &ATOMIC_WRITE_AFTER_RENAME_HOOK,
        AtomicWriteTestBoundary::AfterDirectorySync => &ATOMIC_WRITE_AFTER_DIRECTORY_SYNC_HOOK,
    };
    if let Some(hook) = slot.with(|slot| slot.borrow_mut().take()) {
        hook(path);
    }
}

#[cfg(test)]
fn install_promotion_boundary_hook(
    boundary: PromotionTestBoundary,
    hook: impl FnOnce(&Path) + 'static,
) {
    let slot = match boundary {
        PromotionTestBoundary::BeforeRename => &PROMOTION_BEFORE_RENAME_HOOK,
        PromotionTestBoundary::BeforeDestinationRename => &PROMOTION_BEFORE_DESTINATION_RENAME_HOOK,
        PromotionTestBoundary::AfterRename => &PROMOTION_AFTER_RENAME_HOOK,
        PromotionTestBoundary::AfterDirectorySync => &PROMOTION_AFTER_DIRECTORY_SYNC_HOOK,
    };
    slot.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_promotion_boundary_hook(boundary: PromotionTestBoundary, path: &Path) {
    let slot = match boundary {
        PromotionTestBoundary::BeforeRename => &PROMOTION_BEFORE_RENAME_HOOK,
        PromotionTestBoundary::BeforeDestinationRename => &PROMOTION_BEFORE_DESTINATION_RENAME_HOOK,
        PromotionTestBoundary::AfterRename => &PROMOTION_AFTER_RENAME_HOOK,
        PromotionTestBoundary::AfterDirectorySync => &PROMOTION_AFTER_DIRECTORY_SYNC_HOOK,
    };
    if let Some(hook) = slot.with(|slot| slot.borrow_mut().take()) {
        hook(path);
    }
}

/// Deterministically stop immediately after a successful promotion rename,
/// before the parent directory is synced. Resume tests use this to exercise
/// the promoted-name branch without pretending the ordinary post-promotion
/// failpoint was early enough.
#[cfg(test)]
pub(super) fn fail_next_promotion_after_rename() {
    FAIL_NEXT_PROMOTION_AFTER_RENAME.with(|fail| fail.set(true));
}

#[cfg(test)]
fn install_bounded_json_after_open_hook(hook: impl FnOnce(&Path) + 'static) {
    BOUNDED_JSON_AFTER_OPEN_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_bounded_json_after_open_hook(path: &Path) {
    if let Some(hook) = BOUNDED_JSON_AFTER_OPEN_HOOK.with(|slot| slot.borrow_mut().take()) {
        hook(path);
    }
}

/// Deterministically substitute a pathname only while an already-held
/// descriptor is undergoing semantic inspection. This proves callers use the
/// descriptor rather than silently reopening the copied artifact by name.
#[cfg(test)]
pub(super) fn install_pinned_inspection_path_swap_hooks(
    before: impl FnMut(&Path) + 'static,
    after: impl FnMut(&Path) + 'static,
) {
    PINNED_INSPECTION_BEFORE_SEMANTIC_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(before)));
    PINNED_INSPECTION_AFTER_SEMANTIC_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(after)));
}

/// Clear descriptor-inspection test hooks even when their one intended swap
/// has already fired.  The hooks are thread-local because they model an
/// in-process pathname attacker; leaving a closure installed would let a
/// later serial recovery test mutate an unrelated artifact.
#[cfg(test)]
pub(super) fn clear_pinned_inspection_path_swap_hooks() {
    PINNED_INSPECTION_BEFORE_SEMANTIC_HOOK.with(|slot| *slot.borrow_mut() = None);
    PINNED_INSPECTION_AFTER_SEMANTIC_HOOK.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
fn run_pinned_inspection_path_swap_hook(before: bool, path: &Path) {
    let slot = if before {
        &PINNED_INSPECTION_BEFORE_SEMANTIC_HOOK
    } else {
        &PINNED_INSPECTION_AFTER_SEMANTIC_HOOK
    };
    slot.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(path);
        }
    });
}

/// Exercise the only interval between the durable workflow identity check and
/// the descriptor-bound target predicate.  Production has no hook: it keeps
/// the execution lock's original descriptor authoritative throughout.
#[cfg(test)]
pub(super) fn install_target_database_after_identity_admission_hook(
    hook: impl FnOnce(&Path) + 'static,
) {
    TARGET_DATABASE_AFTER_IDENTITY_ADMISSION_HOOK
        .with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
pub(super) fn clear_target_database_after_identity_admission_hook() {
    TARGET_DATABASE_AFTER_IDENTITY_ADMISSION_HOOK.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
fn run_target_database_after_identity_admission_hook(path: &Path) {
    if let Some(hook) =
        TARGET_DATABASE_AFTER_IDENTITY_ADMISSION_HOOK.with(|slot| slot.borrow_mut().take())
    {
        hook(path);
    }
}

/// Force a pinned SQLite open to use a VFS-resolved replacement path, then
/// run an attacker action after `xOpen` but before the descriptor-binding
/// fence.  The regression test restores the public pathname at that point so
/// a final pathname fence alone would incorrectly authenticate the original
/// pin while SQLite has already selected the replacement inode.
#[cfg(test)]
fn install_pinned_sqlite_open_mismatch_hook(
    vfs_resolved_path: PathBuf,
    after_open: impl FnOnce() + 'static,
) {
    PINNED_SQLITE_OPEN_PATH_OVERRIDE.with(|slot| *slot.borrow_mut() = Some(vfs_resolved_path));
    PINNED_SQLITE_AFTER_OPEN_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(after_open)));
}

#[cfg(test)]
fn pinned_sqlite_open_path_for_test(path: PathBuf) -> PathBuf {
    PINNED_SQLITE_OPEN_PATH_OVERRIDE.with(|slot| slot.borrow_mut().take().unwrap_or(path))
}

#[cfg(test)]
fn run_pinned_sqlite_after_open_hook() {
    if let Some(hook) = PINNED_SQLITE_AFTER_OPEN_HOOK.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}

#[cfg(test)]
fn record_pinned_sqlite_semantic_open_for_test() {
    PINNED_SQLITE_SEMANTIC_OPEN_COUNT.with(|count| count.set(count.get().saturating_add(1)));
}

#[cfg(test)]
fn reset_pinned_sqlite_semantic_open_count_for_test() {
    PINNED_SQLITE_SEMANTIC_OPEN_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
fn pinned_sqlite_semantic_open_count_for_test() -> usize {
    PINNED_SQLITE_SEMANTIC_OPEN_COUNT.with(std::cell::Cell::get)
}

/// Install the causal legacy-classification seam used to prove that no
/// predecessor prepass can be combined with a later semantic WAL snapshot.
#[cfg(test)]
pub(super) fn install_legacy_classification_before_proof_hook(hook: impl FnOnce() + 'static) {
    LEGACY_CLASSIFICATION_BEFORE_PROOF_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_legacy_classification_before_proof_hook() {
    if let Some(hook) =
        LEGACY_CLASSIFICATION_BEFORE_PROOF_HOOK.with(|slot| slot.borrow_mut().take())
    {
        hook();
    }
}

/// Test seam for the nested target-backup snapshot directory durability
/// boundary. Returning `true` simulates a failed directory fsync; the hook is
/// invoked before the sync attempt so tests can prove no manifest was made
/// durable ahead of it.
#[cfg(test)]
pub(super) fn install_target_backup_snapshot_directory_sync_hook(
    hook: impl FnOnce(&Path) -> bool + 'static,
) {
    TARGET_BACKUP_SNAPSHOT_DIRECTORY_SYNC_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

fn sync_target_backup_snapshot_directory(path: &Path) -> Result<(), RecoveryError> {
    #[cfg(test)]
    if let Some(fail) = TARGET_BACKUP_SNAPSHOT_DIRECTORY_SYNC_HOOK
        .with(|slot| slot.borrow_mut().take())
        .map(|hook| hook(path))
    {
        if fail {
            return Err(RecoveryError::FileOperationFailed);
        }
    }
    sync_directory(path)
}

type FencedTransitionV2HistorySqlRow = (
    i64,
    Vec<u8>,
    Option<i64>,
    i64,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    i64,
);

const LEGACY_LEASE_COLUMNS_WITH_ACQUIRED_AT: &[&str] = &[
    "tenant",
    "nf_kind",
    "key_type",
    "stable_id",
    "active",
    "credential_id",
    "owner",
    "fence",
    "expires_at_unix_ms",
    "guard_expires_at",
    "acquired_at",
];

const LEGACY_LEASE_COLUMNS_BEFORE_ACQUIRED_AT: &[&str] = &[
    "tenant",
    "nf_kind",
    "key_type",
    "stable_id",
    "active",
    "credential_id",
    "owner",
    "fence",
    "expires_at_unix_ms",
    "guard_expires_at",
];

// Recovery digests are format commitments.  A pre-acquisition lease table is
// read through the second query, but is labeled with the current query so a
// writable migration that appends `NULL` has the identical digest.
const LEASES_HASH_QUERY: &str =
    "SELECT * FROM leases ORDER BY tenant, nf_kind, key_type, stable_id";
const PRE_ACQUISITION_LEASES_HASH_QUERY: &str = "SELECT tenant, nf_kind, key_type, stable_id, active, credential_id, owner, fence, expires_at_unix_ms, guard_expires_at, CAST(NULL AS TEXT) AS acquired_at FROM leases ORDER BY tenant, nf_kind, key_type, stable_id";
const RECOVERY_V2_INVARIANT_LEASES_HASH_QUERY: &str = "SELECT tenant, nf_kind, key_type, stable_id, credential_id, owner, fence, expires_at_unix_ms, guard_expires_at, acquired_at FROM leases ORDER BY tenant, nf_kind, key_type, stable_id";
const PRE_ACQUISITION_RECOVERY_V2_INVARIANT_LEASES_HASH_QUERY: &str = "SELECT tenant, nf_kind, key_type, stable_id, credential_id, owner, fence, expires_at_unix_ms, guard_expires_at, CAST(NULL AS TEXT) AS acquired_at FROM leases ORDER BY tenant, nf_kind, key_type, stable_id";

pub(super) struct InspectionInput<'a> {
    pub(super) key: &'a RecoveryIntegrityKey,
    pub(super) replica: &'a RecoveryReplica,
    pub(super) identity: SessionConsensusIdentity,
    pub(super) expected_members: &'a BTreeSet<SessionConsensusNodeId>,
    pub(super) limits: RecoveryLimits,
}

pub(super) struct ResetInput<'a> {
    pub(super) key: &'a RecoveryIntegrityKey,
    pub(super) plan: &'a RecoveryPlan,
    pub(super) source: &'a RecoveryReplica,
    pub(super) replicas: &'a [RecoveryReplica],
    pub(super) targets: &'a [&'a RecoveryReplica],
    pub(super) backup_root: &'a Path,
    pub(super) limits: RecoveryLimits,
    #[cfg(test)]
    pub(super) failpoint: Option<RecoveryFailpoint>,
}

#[cfg(test)]
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecoveryFailpoint {
    AfterTargetBackupCopy,
    AfterCheckpointCopy,
    /// Models a process loss at the former standalone `Verified` workflow
    /// publication point.  At this boundary the checkpoint artifacts exist,
    /// but their authenticated evidence has deliberately not been published.
    AfterCheckpointCopyBeforeVerification,
    AfterBackup,
    AfterStagedCopy,
    AfterSnapshotPromotion,
    AfterSnapshotInstall,
    AfterDatabaseTemporaryPrepared,
    AfterDatabasePromotion,
    AfterDatabaseInstall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkflowRecord {
    version: u16,
    plan_digest: RecoveryDigest,
    /// Work bounds chosen by the caller which performed execute.  They are
    /// MACed with the workflow so every later finalize/resume inspection uses
    /// the same (or stricter would require a new authenticated workflow)
    /// envelope rather than silently widening to RecoveryLimits::default().
    limits: WorkflowLimits,
    source_branch_digest: RecoveryDigest,
    source_authority_profile: RecoveryAuthorityProfile,
    source_fixed_placement_policy: Option<RecoveryFixedPlacementPolicy>,
    source_protected_roster_digest: RecoveryDigest,
    /// Captured only for an explicit legacy recovery after every installed
    /// database has bootstrapped into the same current-format predecessor.
    /// This is MACed before the V2 command is proposed, so a retry cannot
    /// derive a new predecessor from mutable runtime state.
    legacy_finalization_predecessor: Option<FinalizationPredecessorCapsule>,
    /// Common, HMAC-authenticated terminal evidence captured from every
    /// exact V2 replica immediately before the first recovery sidecar is
    /// released.  This is the sole historical reconstruction authority once
    /// a consumed replica legitimately compacts the physical V2 marker.
    terminal_proof: Option<RecoveryTerminalProofV1>,
    target_tokens: Vec<RecoveryDigest>,
    state: RecoveryExecutionState,
    audit_resume_state: Option<RecoveryExecutionState>,
    rejoin_proven: bool,
    checkpoint_database_digest: Option<RecoveryDigest>,
    checkpoint_database_identity: Option<RecoveryDigest>,
    checkpoint_snapshot_digest: Option<RecoveryDigest>,
    checkpoint_snapshot_identity: Option<RecoveryDigest>,
    staged_database_digest: Option<RecoveryDigest>,
    staged_database_identity: Option<RecoveryDigest>,
    staged_snapshot_digest: Option<RecoveryDigest>,
    staged_snapshot_identity: Option<RecoveryDigest>,
    /// The source checkpoint's selected snapshot, if any.  This names the
    /// checkpoint artifact and is committed together with its digest and
    /// incarnation before `BackupVerified` becomes durable.
    source_snapshot_name: Option<String>,
    /// The snapshot selected by the *staged* database.  Staging may
    /// intentionally omit a source-local historical snapshot when the
    /// committed log row is physically retained, so this cannot be inferred
    /// from `source_snapshot_name`.
    staged_snapshot_name: Option<String>,
    checkpoint_progress: FileProgress,
    staged_progress: FileProgress,
    target_backups: BTreeMap<String, FileProgress>,
    target_installs: BTreeMap<String, TargetInstallState>,
    target_database_identities: BTreeMap<String, RecoveryDigest>,
    /// Destination identity recorded while its temporary database file is
    /// still pinned, before promotion.  A resume may promote only this exact
    /// inode; it must never infer that a byte-identical replacement is safe.
    target_temporary_database_identities: BTreeMap<String, RecoveryDigest>,
    /// The exact destination disposition authenticated with each prepared
    /// database temporary.  This is deliberately per pathname, rather than
    /// derived from the target's selected snapshot or another mutable plan
    /// field during resume.
    target_temporary_database_destinations: BTreeMap<String, PromotionDisposition>,
    /// Every target snapshot is committed independently from the staged
    /// source.  `None` is itself authenticated for databases without a
    /// current snapshot, avoiding an absence/default ambiguity on resume.
    target_snapshot_identities: BTreeMap<String, Option<RecoveryDigest>>,
    /// Snapshot temporary inode MAC persisted before promotion.
    target_temporary_snapshot_identities: BTreeMap<String, RecoveryDigest>,
    /// The exact destination disposition authenticated with each prepared
    /// snapshot temporary.
    target_temporary_snapshot_destinations: BTreeMap<String, PromotionDisposition>,
}

/// Bounded, revisioned recovery evidence sealed inside the workflow HMAC.
/// It intentionally records the leader-owned original command time and full
/// Raft identities, rather than attempting to infer either from a later
/// compacted SQLite state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RecoveryTerminalProofV1 {
    proof_revision: u16,
    proof_domain: String,
    identity: SessionConsensusIdentity,
    recovery_epoch: u64,
    plan_digest: RecoveryDigest,
    predecessor: FinalizationPredecessorCapsule,
    finalize_log_id: LogId<SessionConsensusNodeId>,
    command_schema_version: u16,
    request_id: SessionConsensusRequestId,
    original_command_logical_time: Timestamp,
    intent_payload_digest: RecoveryDigest,
    recovery_application_sequence: u64,
    effective_logical_time: Timestamp,
    applied_digest: RecoveryDigest,
    outcome_commitment: RecoveryDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct WorkflowLimits {
    max_database_bytes: u64,
    max_snapshot_bytes: u64,
    max_rows: u64,
    max_value_bytes: u64,
    max_total_value_bytes: u64,
    max_duration_seconds: u64,
    max_duration_nanos: u32,
}

impl WorkflowLimits {
    fn from_recovery(limits: RecoveryLimits) -> Self {
        Self {
            max_database_bytes: limits.max_database_bytes(),
            max_snapshot_bytes: limits.max_snapshot_bytes(),
            max_rows: limits.max_rows(),
            max_value_bytes: limits.max_value_bytes(),
            max_total_value_bytes: limits.max_total_value_bytes(),
            max_duration_seconds: limits.max_duration().as_secs(),
            max_duration_nanos: limits.max_duration().subsec_nanos(),
        }
    }

    fn recovery_limits(self) -> Result<RecoveryLimits, RecoveryError> {
        RecoveryLimits::try_new_with_work_budget(
            self.max_database_bytes,
            self.max_snapshot_bytes,
            self.max_rows,
            self.max_value_bytes,
            self.max_total_value_bytes,
            Duration::new(self.max_duration_seconds, self.max_duration_nanos),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FileProgress {
    Pending,
    Copying,
    Verified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TargetInstallState {
    Pending,
    SnapshotCopying,
    SnapshotPromoting,
    SnapshotInstalled,
    DatabaseCopying,
    DatabaseInstalled,
}

/// The public pathname state captured while the prepared temporary inode is
/// still held.  Resuming a promotion must use this MACed disposition; it must
/// never infer a destination from a current snapshot selected under a
/// different filename.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PromotionDisposition {
    Absent,
    Present { displaced_identity: RecoveryDigest },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealedWorkflowRecord {
    record: WorkflowRecord,
    mac: RecoveryDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupFileEvidence {
    role: String,
    byte_length: u64,
    digest: RecoveryDigest,
    identity: RecoveryDigest,
    original_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupManifestBody {
    version: u16,
    plan_digest: RecoveryDigest,
    target_token: RecoveryDigest,
    files: Vec<BackupFileEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealedBackupManifest {
    body: BackupManifestBody,
    mac: RecoveryDigest,
}

struct CanonicalReplicaPaths {
    database: PathBuf,
    snapshots: PathBuf,
}

struct InspectionBudget {
    limits: RecoveryLimits,
    started: Instant,
    rows: u64,
    value_bytes: u64,
}

/// The exact work accounting consumed by the shared V2 invariant-state
/// projection.  Offline inspection supplies its caller-approved budget;
/// consensus apply supplies a fixed protocol budget so every voter hashes the
/// same complete projection under the same finite capacity.
trait RecoveryV2InvariantWorkBudget {
    fn consume_row(&mut self) -> Result<(), RecoveryError>;
    fn consume_value(&mut self, length: usize) -> Result<(), RecoveryError>;
    fn map_sql_error(&self, error: rusqlite::Error) -> RecoveryError;
}

struct RecoveryV2InvariantProtocolBudget {
    rows: u64,
    value_bytes: u64,
}

#[cfg(unix)]
struct ReplicaExecutionLock {
    path: PathBuf,
    _file: nix::fcntl::Flock<File>,
    device: u64,
    inode: u64,
    /// The original target database remains pinned for the entire execute
    /// operation.  Promotion exchanges against this exact descriptor instead
    /// of overwriting whichever inode happens to occupy the pathname later.
    database: PinnedSnapshotFile,
}

impl InspectionBudget {
    fn new(limits: RecoveryLimits) -> Self {
        Self {
            limits,
            started: Instant::now(),
            rows: 0,
            value_bytes: 0,
        }
    }

    fn check(&self) -> Result<(), RecoveryError> {
        if self.started.elapsed() >= self.limits.max_duration() {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        Ok(())
    }

    fn consume_row(&mut self) -> Result<(), RecoveryError> {
        self.check()?;
        self.rows = self
            .rows
            .checked_add(1)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if self.rows > self.limits.max_rows() {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        Ok(())
    }

    fn consume_value(&mut self, length: usize) -> Result<(), RecoveryError> {
        self.check()?;
        let length = u64::try_from(length).map_err(|_| RecoveryError::WorkLimitExceeded)?;
        if length > self.limits.max_value_bytes() {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        self.value_bytes = self
            .value_bytes
            .checked_add(length)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if self.value_bytes > self.limits.max_total_value_bytes() {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        Ok(())
    }

    fn consume_table_scan(
        &mut self,
        rows: u64,
        maximum_value_bytes: u64,
        total_value_bytes: u64,
    ) -> Result<(), RecoveryError> {
        self.check()?;
        if maximum_value_bytes > self.limits.max_value_bytes() {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        self.rows = self
            .rows
            .checked_add(rows)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        self.value_bytes = self
            .value_bytes
            .checked_add(total_value_bytes)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if self.rows > self.limits.max_rows()
            || self.value_bytes > self.limits.max_total_value_bytes()
        {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        Ok(())
    }
}

impl RecoveryV2InvariantWorkBudget for InspectionBudget {
    fn consume_row(&mut self) -> Result<(), RecoveryError> {
        Self::consume_row(self)
    }

    fn consume_value(&mut self, length: usize) -> Result<(), RecoveryError> {
        Self::consume_value(self, length)
    }

    fn map_sql_error(&self, error: rusqlite::Error) -> RecoveryError {
        inspection_sql_error(error, self)
    }
}

impl RecoveryV2InvariantProtocolBudget {
    fn new() -> Self {
        Self {
            rows: 0,
            value_bytes: 0,
        }
    }
}

impl RecoveryV2InvariantWorkBudget for RecoveryV2InvariantProtocolBudget {
    fn consume_row(&mut self) -> Result<(), RecoveryError> {
        self.rows = self
            .rows
            .checked_add(1)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if self.rows > RECOVERY_V2_INVARIANT_PROTOCOL_MAX_ROWS {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        Ok(())
    }

    fn consume_value(&mut self, length: usize) -> Result<(), RecoveryError> {
        let length = u64::try_from(length).map_err(|_| RecoveryError::WorkLimitExceeded)?;
        if length > RECOVERY_V2_INVARIANT_PROTOCOL_MAX_VALUE_BYTES {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        self.value_bytes = self
            .value_bytes
            .checked_add(length)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if self.value_bytes > RECOVERY_V2_INVARIANT_PROTOCOL_MAX_TOTAL_VALUE_BYTES {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        Ok(())
    }

    fn map_sql_error(&self, _error: rusqlite::Error) -> RecoveryError {
        RecoveryError::CorruptReplica
    }
}

fn inspection_sql_error(error: rusqlite::Error, budget: &InspectionBudget) -> RecoveryError {
    if budget.started.elapsed() >= budget.limits.max_duration()
        || matches!(
            error,
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code: rusqlite::ffi::ErrorCode::OperationInterrupted,
                    ..
                },
                _
            )
        )
    {
        RecoveryError::WorkLimitExceeded
    } else {
        RecoveryError::CorruptReplica
    }
}

pub(super) fn seal_plan(
    key: &RecoveryIntegrityKey,
    plan_digest: RecoveryDigest,
    encoded: &[u8],
) -> Result<RecoveryDigest, RecoveryError> {
    Ok(RecoveryDigest::from_bytes(plan_mac(
        key,
        PLAN_MAC_DOMAIN,
        &[&plan_digest.as_bytes(), encoded],
    )?))
}

pub(super) fn verify_plan_seal(
    key: &RecoveryIntegrityKey,
    plan_digest: RecoveryDigest,
    encoded: &[u8],
    seal: RecoveryDigest,
) -> Result<(), RecoveryError> {
    let mut verifier = hmac::Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| RecoveryError::StalePlan)?;
    verifier.update(PLAN_MAC_DOMAIN);
    for part in [&plan_digest.as_bytes()[..], encoded] {
        verifier.update(
            &u64::try_from(part.len())
                .map_err(|_| RecoveryError::StalePlan)?
                .to_be_bytes(),
        );
        verifier.update(part);
    }
    verifier
        .verify_slice(&seal.as_bytes())
        .map_err(|_| RecoveryError::StalePlan)?;
    Ok(())
}

pub(super) fn inspect_replica(
    input: InspectionInput<'_>,
) -> Result<RecoveryReplicaEvidence, RecoveryError> {
    let paths = canonical_replica_paths(input.replica, false)?;
    // Acquire the inode before deriving any evidence from it.  In particular,
    // do not `stat` a pathname and then let SQLite resolve that pathname a
    // second time: a same-UID rename between the two operations would make a
    // different database authoritative while preserving the first inode MAC.
    let database_file = PinnedSnapshotFile::open(&paths.database)
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    inspect_replica_from_pinned(input, paths, &database_file, None)
}

/// Test-only access to the descriptor-bound inspection snapshot.  This is a
/// deliberately narrow causal seam: production callers use their concrete
/// terminal proof closures below, while the regression can prove a writer's
/// WAL commit is not combined with evidence obtained before that commit.
#[cfg(test)]
pub(super) fn inspect_replica_with_descriptor_snapshot_proof_for_test<T>(
    input: InspectionInput<'_>,
    proof: impl FnOnce(&RecoveryReplicaEvidence, &Connection) -> Result<T, RecoveryError>,
) -> Result<T, RecoveryError> {
    let paths = canonical_replica_paths(input.replica, false)?;
    let database_file = PinnedSnapshotFile::open(&paths.database)
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    inspect_replica_from_pinned_with(input, paths, &database_file, None, proof)
        .map(|(_evidence, result)| result)
}

/// Inspect a replica through an already-held database descriptor.  Callers
/// that must span an irreversible boundary retain the pin and use this helper
/// for both sides of that boundary.
fn inspect_replica_from_pinned(
    input: InspectionInput<'_>,
    paths: CanonicalReplicaPaths,
    database_file: &PinnedSnapshotFile,
    snapshot_file: Option<&mut PinnedSnapshotFile>,
) -> Result<RecoveryReplicaEvidence, RecoveryError> {
    inspect_replica_from_pinned_with(
        input,
        paths,
        database_file,
        snapshot_file,
        |_evidence, _conn| Ok(()),
    )
    .map(|(evidence, ())| evidence)
}

/// Derive the inspection evidence and the caller's terminal predicate from
/// one descriptor-bound SQLite read transaction.  The inspection establishes
/// the WAL snapshot before an optional test writer can run; callers must not
/// reopen the pathname afterwards and accidentally combine that snapshot's
/// evidence with a later database state.
fn inspect_replica_from_pinned_with<T>(
    input: InspectionInput<'_>,
    paths: CanonicalReplicaPaths,
    database_file: &PinnedSnapshotFile,
    snapshot_file: Option<&mut PinnedSnapshotFile>,
    proof: impl FnOnce(&RecoveryReplicaEvidence, &Connection) -> Result<T, RecoveryError>,
) -> Result<(RecoveryReplicaEvidence, T), RecoveryError> {
    let mut budget = InspectionBudget::new(input.limits);
    let path_binding = recovery_path_binding(input.key, &paths)?;
    let database_path = paths.database.clone();
    let metadata = database_file
        .file
        .metadata()
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > input.limits.max_database_bytes()
    {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    let file_identity = pinned_file_identity(input.key, database_file)?;
    let conn = open_read_only_pinned(database_file)?;
    #[cfg(test)]
    run_pinned_inspection_path_swap_hook(true, &database_path);
    let started = budget.started;
    let max_duration = input.limits.max_duration();
    conn.progress_handler(1_000, Some(move || started.elapsed() >= max_duration));
    validate_database_snapshot(&conn, &budget)?;
    let evidence = if table_exists(&conn, "consensus_identity")? {
        inspect_current(
            input,
            &conn,
            paths,
            path_binding,
            file_identity,
            &mut budget,
            snapshot_file,
        )
    } else {
        inspect_legacy(input, &conn, path_binding, file_identity, &mut budget)
    }?;
    #[cfg(test)]
    run_pinned_inspection_path_swap_hook(false, &database_path);
    // Keep every suffix/certificate/outcome/purge/snapshot proof on the
    // transaction that produced `evidence`.  In particular, do not create a
    // nested transaction here: the existing `BEGIN DEFERRED` transaction is
    // the single snapshot whose identity was bound above.
    let result = proof(&evidence, &conn)?;
    database_file
        .verify_path_identity(&database_path)
        .map_err(|_| RecoveryError::SourceChanged)?;
    Ok((evidence, result))
}

pub(super) fn replica_has_recovery_latch(
    replica: &RecoveryReplica,
    identity: SessionConsensusIdentity,
) -> Result<bool, RecoveryError> {
    let paths = canonical_replica_paths(replica, false)?;
    // Planning is the repair authority for a stopped fleet. Runtime startup
    // deliberately fails closed when a recovered database lacks its terminal
    // tombstone, but that condition must not make an operator-authorized
    // offline campaign impossible to inspect and repair. Here we only fence
    // a *currently active* sidecar; full terminal/database coherence remains
    // connection-bound in normal admission and during recovery finalization.
    match consensus::active_operator_recovery_latch_sync(&paths.database)
        .map_err(|_| RecoveryError::CorruptReplica)?
    {
        Some(latch) if latch.identity == identity => Ok(true),
        Some(_) => Err(RecoveryError::WrongCluster),
        None => Ok(false),
    }
}

fn inspect_current(
    input: InspectionInput<'_>,
    conn: &Connection,
    paths: CanonicalReplicaPaths,
    path_binding: RecoveryDigest,
    file_identity: RecoveryDigest,
    budget: &mut InspectionBudget,
    snapshot_file: Option<&mut PinnedSnapshotFile>,
) -> Result<RecoveryReplicaEvidence, RecoveryError> {
    budget.check()?;
    let preflight_total_bytes = preflight_current_tables(conn, budget)?;
    validate_exact_recovery_schema(conn, false)?;
    let (authority_profile, fixed_placement_policy) = recovery_authority_descriptor(conn)?;
    let v2_ledger_layout = consensus::fenced_transition_v2_ledger_layout_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let receipt_ledger_layout = consensus::fenced_transition_receipt_ledger_layout_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let protected_roster_layout = consensus::protected_roster_recovery_layout_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let (schema_version, cluster, configuration, epoch): (i64, Vec<u8>, Vec<u8>, i64) = conn
        .query_row(
            "SELECT schema_version, cluster_id, configuration_id, configuration_epoch FROM consensus_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let expected_schema_version = match protected_roster_layout {
        consensus::ProtectedRosterRecoveryLayout::Activated => {
            i64::from(SESSION_CONSENSUS_SCHEMA_VERSION) + 3
        }
        consensus::ProtectedRosterRecoveryLayout::Legacy
        | consensus::ProtectedRosterRecoveryLayout::Prepared => match v2_ledger_layout {
            consensus::FencedTransitionV2LedgerLayout::Activated => {
                i64::from(SESSION_CONSENSUS_SCHEMA_VERSION) + 2
            }
            consensus::FencedTransitionV2LedgerLayout::Absent => match receipt_ledger_layout {
                consensus::FencedTransitionReceiptLedgerLayout::Published684
                | consensus::FencedTransitionReceiptLedgerLayout::Prepared => {
                    i64::from(SESSION_CONSENSUS_SCHEMA_VERSION)
                }
                consensus::FencedTransitionReceiptLedgerLayout::Activated => {
                    i64::from(SESSION_CONSENSUS_SCHEMA_VERSION) + 1
                }
            },
        },
    };
    if schema_version != expected_schema_version {
        return Err(RecoveryError::CorruptReplica);
    }
    let cluster: [u8; 32] = cluster
        .try_into()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let configuration: [u8; 32] = configuration
        .try_into()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let epoch = u64::try_from(epoch)
        .ok()
        .and_then(|value| SessionConsensusConfigurationEpoch::new(value).ok())
        .ok_or(RecoveryError::CorruptReplica)?;
    let storage_identity = SessionConsensusIdentity::new(
        crate::consensus::SessionConsensusClusterId::from_bytes(cluster),
        SessionConsensusConfigurationId::from_bytes(configuration),
        epoch,
    );
    // Keep the optional snapshot descriptor alive through both the inode
    // commitment and the branch walk below.  In particular, finalization
    // supplies the installed target pin here; reopening its pathname between
    // those two checks would let a byte-identical replacement become semantic
    // authority after the workflow committed the original inode.
    let mut snapshot_file = snapshot_file;
    let current_snapshot_identity = match snapshot_file.as_mut() {
        Some(file) => current_snapshot_identity(
            input.key,
            conn,
            storage_identity,
            &paths.snapshots,
            authority_profile == RecoveryAuthorityProfile::FixedImmutable,
            input.limits,
            Some(file),
        )?,
        None => current_snapshot_identity(
            input.key,
            conn,
            storage_identity,
            &paths.snapshots,
            authority_profile == RecoveryAuthorityProfile::FixedImmutable,
            input.limits,
            None,
        )?,
    };
    if storage_identity.cluster_id() != input.identity.cluster_id() {
        return Err(RecoveryError::WrongCluster);
    }
    let membership_scope = consensus::read_membership_scope_sync(conn, storage_identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if membership_scope.current_identity != input.identity
        || membership_scope.current_members != *input.expected_members
    {
        return Err(RecoveryError::WrongCluster);
    }
    let membership = consensus::read_membership_sync(conn, storage_identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if v2_ledger_layout == consensus::FencedTransitionV2LedgerLayout::Activated {
        validate_fenced_transition_v2_recovery_state(conn, storage_identity)?;
    }
    validate_consensus_sealed_records(conn, budget)?;
    consensus::validate_protected_roster_recovery_state_sync(conn, storage_identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    validate_legacy_lease_state(conn, budget)?;
    if receipt_ledger_layout != consensus::FencedTransitionReceiptLedgerLayout::Published684 {
        consensus::validate_fenced_transition_receipts_sync(conn, storage_identity)
            .map_err(|_| RecoveryError::CorruptReplica)?;
    }
    let committed = consensus::read_committed_sync(conn, storage_identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let applied = consensus::read_applied_sync(conn, storage_identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let purged = consensus::read_purged_sync(conn, storage_identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let retained_log_rows = preflight_authoritative_consensus_log(
        conn,
        budget,
        preflight_total_bytes,
        purged.as_ref(),
    )?;
    let current_snapshot = consensus::read_current_snapshot_sync(conn, storage_identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let (retained_log_ids, retained_memberships) = validate_retained_consensus_log(
        conn,
        storage_identity,
        purged.as_ref(),
        current_snapshot
            .as_ref()
            .and_then(|(meta, _, _, _)| meta.last_log_id.as_ref()),
        retained_log_rows,
        budget,
    )?;
    let snapshot_log = current_snapshot
        .as_ref()
        .and_then(|(meta, _, _, _)| meta.last_log_id.as_ref());
    let last_logical = retained_log_ids
        .iter()
        .copied()
        .chain(purged.iter().copied())
        .chain(snapshot_log.copied())
        .max_by_key(|log_id| log_id.index);
    consensus::validate_durable_log_pointer_lineage(
        committed.as_ref(),
        applied.as_ref(),
        purged.as_ref(),
        snapshot_log,
        consensus::DurableMembershipLineage {
            persisted: &membership,
            snapshot: current_snapshot
                .as_ref()
                .map(|(meta, _, _, _)| &meta.last_membership),
            retained: &retained_memberships,
        },
        &retained_log_ids,
        last_logical.as_ref(),
    )
    .map_err(|_| RecoveryError::CorruptReplica)?;
    let recovery = consensus::read_operator_recovery_sync(conn, storage_identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let replication_head = validate_replication_sequence_domain(
        conn,
        budget,
        recovery.watch_cursor_invalidation_floor,
    )?;
    let (application_sequence, last_digest, machine_logical_time, watch_sequence): (
        i64,
        Vec<u8>,
        Option<String>,
        i64,
    ) = conn
        .query_row(
            "SELECT application_sequence, last_digest, logical_time, watch_sequence FROM consensus_machine WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let application_sequence =
        u64::try_from(application_sequence).map_err(|_| RecoveryError::CorruptReplica)?;
    let machine_last_digest = RecoveryDigest::from_bytes(
        last_digest
            .try_into()
            .map_err(|_| RecoveryError::CorruptReplica)?,
    );
    let machine_logical_time = machine_logical_time
        .map(|value| Timestamp::from_str(&value).map_err(|_| RecoveryError::CorruptReplica))
        .transpose()?;
    let watch_sequence =
        u64::try_from(watch_sequence).map_err(|_| RecoveryError::CorruptReplica)?;
    if watch_sequence != replication_head {
        return Err(RecoveryError::CorruptReplica);
    }
    let protected_roster_digest = protected_roster_digest(conn, budget)?;
    let authority_commitment = RecoveryDigest::from_bytes(
        consensus::operator_recovery_v2_authority_commitment_sync(
            conn,
            storage_identity,
            input.expected_members,
        )
        .map_err(|_| RecoveryError::CorruptReplica)?,
    );
    let branch_digest = match snapshot_file.as_mut() {
        Some(file) => committed_branch_digest(
            conn,
            storage_identity,
            committed.as_ref(),
            &paths.snapshots,
            budget,
            recovery.recovery_epoch,
            recovery.last_plan_digest,
            recovery.pending_epoch,
            recovery.pending_plan_digest,
            recovery.watch_cursor_invalidation_floor,
            authority_profile,
            fixed_placement_policy,
            protected_roster_digest,
            Some(file),
        )?,
        None => committed_branch_digest(
            conn,
            storage_identity,
            committed.as_ref(),
            &paths.snapshots,
            budget,
            recovery.recovery_epoch,
            recovery.last_plan_digest,
            recovery.pending_epoch,
            recovery.pending_plan_digest,
            recovery.watch_cursor_invalidation_floor,
            authority_profile,
            fixed_placement_policy,
            protected_roster_digest,
            None,
        )?,
    };
    let fence_high_water = consensus::observed_fence_high_water_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let credential_high_water = consensus::observed_credential_high_water_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let predecessor_bootstrap_membership_digest = committed
        .as_ref()
        .map(|baseline| {
            consensus::operator_recovery_v2_predecessor_kind_sync(conn, storage_identity, baseline)
                .map_err(|_| RecoveryError::CorruptReplica)
                .map(|kind| match kind {
                    consensus::OperatorRecoveryV2PredecessorKind::RetainedMembership(digest) => {
                        Some(RecoveryDigest::from_bytes(digest))
                    }
                    consensus::OperatorRecoveryV2PredecessorKind::RetainedNonMembership
                    | consensus::OperatorRecoveryV2PredecessorKind::NotRetained => None,
                })
        })
        .transpose()?
        .flatten();
    let logical_state_digest = hash_logical_state(conn, budget)?;
    let recovery_v2_invariant_state_digest = hash_recovery_v2_invariant_state(conn, budget)?;
    budget.check()?;
    Ok(RecoveryReplicaEvidence {
        replica_token: super::replica_token(input.key, &input.replica.replica_id)?,
        backing_identity: RecoveryDigest::from_bytes(input.replica.backing_identity.fingerprint()),
        path_binding,
        file_identity,
        format: RecoveryReplicaFormat::Openraft,
        cluster_digest: Some(RecoveryDigest::from_bytes(cluster)),
        configuration_digest: Some(RecoveryDigest::from_bytes(
            *input.identity.configuration_id().as_bytes(),
        )),
        configuration_epoch: Some(input.identity.configuration_epoch().get()),
        authority_profile,
        fixed_placement_policy,
        current_snapshot_identity,
        recovery_epoch: recovery.recovery_epoch,
        last_plan_digest: RecoveryDigest::from_bytes(recovery.last_plan_digest),
        pending_recovery_epoch: recovery.pending_epoch,
        pending_plan_digest: recovery.pending_plan_digest.map(RecoveryDigest::from_bytes),
        finalize_log_id: recovery.finalize_log_id,
        watch_cursor_invalidation_floor: recovery.watch_cursor_invalidation_floor,
        application_sequence,
        machine_last_digest,
        machine_logical_time,
        watch_sequence,
        authority_commitment,
        committed_log_id: committed,
        predecessor_bootstrap_membership_digest,
        applied_log_id: applied,
        local_head_log_id: last_logical,
        committed_index: committed.as_ref().map(|log_id| log_id.index),
        applied_index: applied.as_ref().map(|log_id| log_id.index),
        local_head_index: last_logical.map(|log_id| log_id.index),
        branch_digest,
        fence_high_water,
        credential_high_water,
        logical_state_digest,
        recovery_v2_invariant_state_digest,
        protected_roster_digest,
    })
}

fn preflight_current_tables(
    conn: &Connection,
    budget: &InspectionBudget,
) -> Result<u64, RecoveryError> {
    let mut total_bytes = 0_u64;
    for query in [
        "SELECT COUNT(*), COALESCE(MAX(MAX(length(cluster_id), length(configuration_id))), 0), COALESCE(SUM(length(cluster_id) + length(configuration_id)), 0) FROM consensus_identity",
        "SELECT COUNT(*), COALESCE(MAX(length(membership_json)), 0), COALESCE(SUM(length(membership_json)), 0) FROM consensus_membership",
        "SELECT COUNT(*), COALESCE(MAX(length(vote_json)), 0), COALESCE(SUM(length(vote_json)), 0) FROM consensus_vote",
        "SELECT COUNT(*), COALESCE(MAX(length(log_id_json)), 0), COALESCE(SUM(length(log_id_json)), 0) FROM consensus_committed",
        "SELECT COUNT(*), COALESCE(MAX(length(log_id_json)), 0), COALESCE(SUM(length(log_id_json)), 0) FROM consensus_purged",
        "SELECT COUNT(*), COALESCE(MAX(length(log_id_json)), 0), COALESCE(SUM(length(log_id_json)), 0) FROM consensus_applied",
        "SELECT COUNT(*), COALESCE(MAX(MAX(length(meta_json), length(file_name), length(checksum))), 0), COALESCE(SUM(length(meta_json) + length(file_name) + length(checksum)), 0) FROM consensus_snapshot",
        "SELECT COUNT(*), COALESCE(MAX(MAX(length(request_id), length(payload_digest), length(response_json))), 0), COALESCE(SUM(length(request_id) + length(payload_digest) + length(response_json)), 0) FROM consensus_request_outcomes",
    ] {
        let (count, maximum, total): (i64, i64, i64) = conn
            .query_row(query, [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|error| inspection_sql_error(error, budget))?;
        let count = u64::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
        let maximum = u64::try_from(maximum).map_err(|_| RecoveryError::CorruptReplica)?;
        let total = u64::try_from(total).map_err(|_| RecoveryError::CorruptReplica)?;
        total_bytes = total_bytes
            .checked_add(total)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if count > budget.limits.max_rows()
            || maximum > budget.limits.max_value_bytes()
            || total_bytes > budget.limits.max_total_value_bytes()
        {
            return Err(RecoveryError::WorkLimitExceeded);
        }
    }
    if table_exists(conn, "consensus_fenced_transition_receipts")? {
        match fenced_receipt_commitment_columns(conn)? {
            FencedReceiptCommitmentColumns::Neither => {
                let has_rows: bool = conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM consensus_fenced_transition_receipts LIMIT 1)",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(|_| RecoveryError::CorruptReplica)?;
                if has_rows {
                    return Err(RecoveryError::CorruptReplica);
                }
            }
            FencedReceiptCommitmentColumns::Both => {
                preflight_fenced_transition_receipt_count(conn)?;
                consensus::validate_fenced_transition_receipt_storage_bounds_sync(conn)
                    .map_err(|_| RecoveryError::CorruptReplica)?;
                let cap = i64::try_from(FENCED_TRANSITION_MAX_HISTORY_ENTRIES)
                    .map_err(|_| RecoveryError::CorruptReplica)?;
                let query = "SELECT COUNT(*), COALESCE(MAX(MAX(length(request_id), length(payload_digest), length(retained_until), length(binding_digest), COALESCE(length(response_json), 0), COALESCE(length(response_digest), 0))), 0), COALESCE(SUM(length(request_id) + length(payload_digest) + length(retained_until) + length(binding_digest) + COALESCE(length(response_json), 0) + COALESCE(length(response_digest), 0)), 0) FROM (SELECT request_id, payload_digest, retained_until, binding_digest, response_json, response_digest FROM consensus_fenced_transition_receipts LIMIT ?1)";
                let (count, maximum, total): (i64, i64, i64) = conn
                    .query_row(query, [cap], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                    })
                    .map_err(|error| inspection_sql_error(error, budget))?;
                let count = u64::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
                let maximum = u64::try_from(maximum).map_err(|_| RecoveryError::CorruptReplica)?;
                let total = u64::try_from(total).map_err(|_| RecoveryError::CorruptReplica)?;
                total_bytes = total_bytes
                    .checked_add(total)
                    .ok_or(RecoveryError::WorkLimitExceeded)?;
                if count > budget.limits.max_rows()
                    || maximum > budget.limits.max_value_bytes()
                    || total_bytes > budget.limits.max_total_value_bytes()
                {
                    return Err(RecoveryError::WorkLimitExceeded);
                }
            }
            FencedReceiptCommitmentColumns::Partial => {
                return Err(RecoveryError::CorruptReplica);
            }
        }
    }
    if table_exists(conn, "consensus_fenced_transition_activation")? {
        let (count, maximum, total): (i64, i64, i64) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(MAX(length(scope_configuration_id), length(voter_set_digest))), 0), COALESCE(SUM(length(scope_configuration_id) + length(voter_set_digest)), 0) FROM consensus_fenced_transition_activation",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| inspection_sql_error(error, budget))?;
        let count = u64::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
        let maximum = u64::try_from(maximum).map_err(|_| RecoveryError::CorruptReplica)?;
        let total = u64::try_from(total).map_err(|_| RecoveryError::CorruptReplica)?;
        total_bytes = total_bytes
            .checked_add(total)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if count > 1
            || maximum > budget.limits.max_value_bytes()
            || total_bytes > budget.limits.max_total_value_bytes()
        {
            return Err(RecoveryError::WorkLimitExceeded);
        }
    }
    if consensus::fenced_transition_v2_ledger_layout_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?
        == consensus::FencedTransitionV2LedgerLayout::Activated
    {
        preflight_fenced_transition_v2_receipt_count(conn)?;
        for query in [
            "SELECT COUNT(*), COALESCE(MAX(MAX(length(request_id), length(payload_digest), length(retained_until), length(binding_digest), COALESCE(length(response_json), 0), COALESCE(length(response_digest), 0))), 0), COALESCE(SUM(length(request_id) + length(payload_digest) + length(retained_until) + length(binding_digest) + COALESCE(length(response_json), 0) + COALESCE(length(response_digest), 0)), 0) FROM consensus_fenced_transition_v2_receipts",
            "SELECT COUNT(*), COALESCE(MAX(MAX(length(scope_configuration_id), length(voter_set_digest), length(profile_digest))), 0), COALESCE(SUM(length(scope_configuration_id) + length(voter_set_digest) + length(profile_digest)), 0) FROM consensus_fenced_transition_v2_activation",
        ] {
            let (count, maximum, total): (i64, i64, i64) = conn
                .query_row(query, [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .map_err(|error| inspection_sql_error(error, budget))?;
            let count = u64::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
            let maximum = u64::try_from(maximum).map_err(|_| RecoveryError::CorruptReplica)?;
            let total = u64::try_from(total).map_err(|_| RecoveryError::CorruptReplica)?;
            total_bytes = total_bytes
                .checked_add(total)
                .ok_or(RecoveryError::WorkLimitExceeded)?;
            if count > budget.limits.max_rows()
                || maximum > budget.limits.max_value_bytes()
                || total_bytes > budget.limits.max_total_value_bytes()
            {
                return Err(RecoveryError::WorkLimitExceeded);
            }
        }
        let (count, maximum, total): (i64, i64, i64) = conn
            .query_row(
                "SELECT COUNT(*), 0, 0 FROM consensus_fenced_transition_v2_history",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| inspection_sql_error(error, budget))?;
        if count != 1 || maximum != 0 || total != 0 {
            return Err(RecoveryError::CorruptReplica);
        }
    }
    preflight_protected_roster_tables(conn, budget, &mut total_bytes)?;
    if table_exists(conn, "consensus_operator_recovery")? {
        let has_finalize_log: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('consensus_operator_recovery') WHERE name = 'finalize_log_id_json')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| inspection_sql_error(error, budget))?;
        let has_finalize_certificate: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('consensus_operator_recovery') WHERE name = 'finalize_entry_json')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| inspection_sql_error(error, budget))?;
        let recovery_width = if has_finalize_certificate {
            "MAX(length(last_plan_digest), COALESCE(length(pending_plan_digest), 0), COALESCE(length(finalize_log_id_json), 0), COALESCE(length(finalize_entry_json), 0))"
        } else if has_finalize_log {
            "MAX(length(last_plan_digest), COALESCE(length(pending_plan_digest), 0), COALESCE(length(finalize_log_id_json), 0))"
        } else {
            "MAX(length(last_plan_digest), COALESCE(length(pending_plan_digest), 0))"
        };
        let recovery_sum = if has_finalize_certificate {
            "length(last_plan_digest) + COALESCE(length(pending_plan_digest), 0) + COALESCE(length(finalize_log_id_json), 0) + COALESCE(length(finalize_entry_json), 0)"
        } else if has_finalize_log {
            "length(last_plan_digest) + COALESCE(length(pending_plan_digest), 0) + COALESCE(length(finalize_log_id_json), 0)"
        } else {
            "length(last_plan_digest) + COALESCE(length(pending_plan_digest), 0)"
        };
        let query = format!(
            "SELECT COUNT(*), COALESCE(MAX({recovery_width}), 0), COALESCE(SUM({recovery_sum}), 0) FROM consensus_operator_recovery"
        );
        let (count, maximum, total): (i64, i64, i64) = conn
            .query_row(&query, [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|error| inspection_sql_error(error, budget))?;
        let count = u64::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
        let maximum = u64::try_from(maximum).map_err(|_| RecoveryError::CorruptReplica)?;
        let total = u64::try_from(total).map_err(|_| RecoveryError::CorruptReplica)?;
        total_bytes = total_bytes
            .checked_add(total)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if count > budget.limits.max_rows()
            || maximum > budget.limits.max_value_bytes()
            || total_bytes > budget.limits.max_total_value_bytes()
        {
            return Err(RecoveryError::WorkLimitExceeded);
        }
    }
    if table_exists(conn, "consensus_membership_scope")? {
        let (count, maximum, total): (i64, i64, i64) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(MAX(length(current_members_json), length(application_authority_members_json), COALESCE(length(predecessor_members_json), 0), COALESCE(length(desired_members_json), 0))), 0), COALESCE(SUM(length(current_members_json) + length(application_authority_members_json) + COALESCE(length(predecessor_members_json), 0) + COALESCE(length(desired_members_json), 0)), 0) FROM consensus_membership_scope",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| inspection_sql_error(error, budget))?;
        let count = u64::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
        let maximum = u64::try_from(maximum).map_err(|_| RecoveryError::CorruptReplica)?;
        let total = u64::try_from(total).map_err(|_| RecoveryError::CorruptReplica)?;
        total_bytes = total_bytes
            .checked_add(total)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if count > 1
            || maximum > budget.limits.max_value_bytes()
            || total_bytes > budget.limits.max_total_value_bytes()
        {
            return Err(RecoveryError::WorkLimitExceeded);
        }
    }
    if table_exists(conn, "consensus_membership_history")? {
        let (count, maximum, total): (i64, i64, i64) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(length(members_json)), 0), COALESCE(SUM(length(members_json)), 0) FROM consensus_membership_history",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| inspection_sql_error(error, budget))?;
        let count = u64::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
        let maximum = u64::try_from(maximum).map_err(|_| RecoveryError::CorruptReplica)?;
        let total = u64::try_from(total).map_err(|_| RecoveryError::CorruptReplica)?;
        total_bytes = total_bytes
            .checked_add(total)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if count > 4_096
            || maximum > budget.limits.max_value_bytes()
            || total_bytes > budget.limits.max_total_value_bytes()
        {
            return Err(RecoveryError::WorkLimitExceeded);
        }
    }
    if table_exists(conn, "consensus_membership_terminal_history")? {
        let (count, maximum, total): (i64, i64, i64) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(length(transition_id) + length(transition_digest)), 0), COALESCE(SUM(length(transition_id) + length(transition_digest)), 0) FROM consensus_membership_terminal_history",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|error| inspection_sql_error(error, budget))?;
        let count = u64::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
        let maximum = u64::try_from(maximum).map_err(|_| RecoveryError::CorruptReplica)?;
        let total = u64::try_from(total).map_err(|_| RecoveryError::CorruptReplica)?;
        total_bytes = total_bytes
            .checked_add(total)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if count > 4_096
            || maximum > budget.limits.max_value_bytes()
            || total_bytes > budget.limits.max_total_value_bytes()
        {
            return Err(RecoveryError::WorkLimitExceeded);
        }
    }
    Ok(total_bytes)
}

/// Bound only the logically authoritative log suffix. A durable purge floor
/// masks its physical prefix from all recovery reads, so retained cleanup work
/// must not make an otherwise valid replica exceed its logical work budget.
fn preflight_authoritative_consensus_log(
    conn: &Connection,
    budget: &InspectionBudget,
    total_bytes: u64,
    purged: Option<&LogId<SessionConsensusNodeId>>,
) -> Result<u64, RecoveryError> {
    let floor = purged
        .map(|log_id| i64::try_from(log_id.index).map_err(|_| RecoveryError::CorruptReplica))
        .transpose()?
        .unwrap_or(-1);
    let (count, maximum, total): (i64, i64, i64) = conn
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(length(entry_json)), 0), COALESCE(SUM(length(entry_json)), 0) FROM consensus_log WHERE log_index > ?1",
            [floor],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| inspection_sql_error(error, budget))?;
    let count = u64::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
    let maximum = u64::try_from(maximum).map_err(|_| RecoveryError::CorruptReplica)?;
    let total = u64::try_from(total).map_err(|_| RecoveryError::CorruptReplica)?;
    let total_bytes = total_bytes
        .checked_add(total)
        .ok_or(RecoveryError::WorkLimitExceeded)?;
    if count > budget.limits.max_rows()
        || maximum > budget.limits.max_value_bytes()
        || total_bytes > budget.limits.max_total_value_bytes()
    {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    Ok(count)
}

/// Strictly decode and bind every retained log row, rather than treating a
/// preflight count plus the last/committed row as evidence for the interior.
/// `read_log_range_for_recovery_sync` validates row header identity, sequence
/// continuity, membership projection and fixed-topology constraints; this
/// layer additionally charges the caller work budget and validates every
/// normal command against the inspected storage identity.
fn validate_retained_consensus_log(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    purged: Option<&LogId<SessionConsensusNodeId>>,
    snapshot_floor: Option<&LogId<SessionConsensusNodeId>>,
    expected_rows: u64,
    budget: &mut InspectionBudget,
) -> Result<RetainedConsensusLogEvidence, RecoveryError> {
    // Read every physically retained row above the durable purge floor.  A
    // snapshot may prove an intentionally absent initial prefix, but it must
    // never make already-retained rows below that snapshot invisible to the
    // offline scan (the preflight count covers those rows too).
    let physical_start = purged
        .map(|log| {
            log.index
                .checked_add(1)
                .ok_or(RecoveryError::CorruptReplica)
        })
        .transpose()?
        .unwrap_or(0);
    let limit =
        usize::try_from(budget.limits.max_rows()).map_err(|_| RecoveryError::WorkLimitExceeded)?;
    let entries = consensus::read_physical_log_range_for_recovery_sync(
        conn,
        identity,
        physical_start,
        None,
        Some(limit),
    )
    .map_err(|_| RecoveryError::CorruptReplica)?;
    if u64::try_from(entries.len()).map_err(|_| RecoveryError::CorruptReplica)? != expected_rows {
        return Err(RecoveryError::CorruptReplica);
    }
    let mut expected_index = match (purged, entries.first(), snapshot_floor) {
        (Some(_), _, _) => physical_start,
        (None, Some(first), Some(snapshot))
            if first.log_id.index
                == snapshot
                    .index
                    .checked_add(1)
                    .ok_or(RecoveryError::CorruptReplica)? =>
        {
            first.log_id.index
        }
        (None, _, _) => 0,
    };
    let mut retained_log_ids = Vec::with_capacity(entries.len());
    let mut retained_memberships = Vec::new();
    // When compaction has not recorded a purge floor and the first physical
    // row follows the current snapshot exactly, that snapshot is the durable
    // predecessor.  Seed the same leader ordering fence used by normal log
    // reads so a lowered-term replacement at the snapshot boundary cannot
    // evade comparison merely because its prefix was compacted by snapshot.
    let mut previous_log = match (purged, entries.first(), snapshot_floor) {
        (Some(floor), _, _) => Some(*floor),
        (None, Some(first), Some(snapshot))
            if first.log_id.index
                == snapshot
                    .index
                    .checked_add(1)
                    .ok_or(RecoveryError::CorruptReplica)? =>
        {
            Some(*snapshot)
        }
        _ => None,
    };
    for entry in &entries {
        if entry.log_id.index != expected_index {
            return Err(RecoveryError::CorruptReplica);
        }
        if let Some(previous) = previous_log {
            if entry.log_id.leader_id.term < previous.leader_id.term
                || (entry.log_id.leader_id.term == previous.leader_id.term
                    && entry.log_id.leader_id != previous.leader_id)
            {
                return Err(RecoveryError::CorruptReplica);
            }
        }
        expected_index = expected_index
            .checked_add(1)
            .ok_or(RecoveryError::CorruptReplica)?;
        budget.consume_row()?;
        let encoded = serde_json::to_vec(entry).map_err(|_| RecoveryError::CorruptReplica)?;
        budget.consume_value(encoded.len())?;
        if let opc_consensus::engine::EntryPayload::Normal(command) = &entry.payload {
            consensus::validate_command_for_log(command, identity)
                .map_err(|_| RecoveryError::CorruptReplica)?;
        }
        if let opc_consensus::engine::EntryPayload::Membership(payload) = &entry.payload {
            retained_memberships.push(opc_consensus::engine::StoredMembership::new(
                Some(entry.log_id),
                payload.clone(),
            ));
        }
        retained_log_ids.push(entry.log_id);
        previous_log = Some(entry.log_id);
    }
    budget.check()?;
    Ok((retained_log_ids, retained_memberships))
}

/// Probe no more than one row beyond the durable protocol limit before an
/// aggregate or hash touches the lifetime fenced-transition receipt ledger.
/// Recovery limits remain resource controls; they must not redefine this
/// consensus-format bound.
fn preflight_fenced_transition_receipt_count(conn: &Connection) -> Result<usize, RecoveryError> {
    let limit = i64::try_from(
        FENCED_TRANSITION_MAX_HISTORY_ENTRIES
            .checked_add(1)
            .ok_or(RecoveryError::CorruptReplica)?,
    )
    .map_err(|_| RecoveryError::CorruptReplica)?;
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM (SELECT request_id FROM consensus_fenced_transition_receipts LIMIT ?1)",
            [limit],
            |row| row.get(0),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let count = usize::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
    if count > FENCED_TRANSITION_MAX_HISTORY_ENTRIES {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok(count)
}

/// Probe the V2 protocol cap before inspecting receipt widths, bodies or
/// hashes.  This stays intentionally independent of caller-selected recovery
/// resource limits: accepting a larger persisted ledger would redefine V2.
fn preflight_fenced_transition_v2_receipt_count(conn: &Connection) -> Result<usize, RecoveryError> {
    let limit = i64::try_from(
        FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES
            .checked_add(1)
            .ok_or(RecoveryError::CorruptReplica)?,
    )
    .map_err(|_| RecoveryError::CorruptReplica)?;
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM (SELECT request_id FROM consensus_fenced_transition_v2_receipts LIMIT ?1)",
            [limit],
            |row| row.get(0),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let count = usize::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
    if count > FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok(count)
}

#[derive(Clone, Copy)]
struct ProtectedRosterPreflightTable {
    count_query: &'static str,
    values_query: &'static str,
    protocol_cap: usize,
    protocol_max_value: ProtectedRosterValueCap,
}

#[derive(Clone, Copy)]
enum ProtectedRosterValueCap {
    Fixed(usize),
    CanonicalRecord,
    CanonicalBusiness,
}

/// Check the protocol-owned roster cardinalities before any aggregate or
/// canonical decoder can inspect the complete table. Every count query sees
/// at most one row beyond its immutable format cap; every width query sees at
/// most that cap. Recovery limits remain an additional caller-owned bound.
fn preflight_protected_roster_tables(
    conn: &Connection,
    budget: &InspectionBudget,
    total_bytes: &mut u64,
) -> Result<(), RecoveryError> {
    let layout = consensus::protected_roster_recovery_layout_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if layout == consensus::ProtectedRosterRecoveryLayout::Legacy {
        return Ok(());
    }

    const ROOT: ProtectedRosterPreflightTable = ProtectedRosterPreflightTable {
        count_query: "SELECT COUNT(*) FROM (SELECT singleton FROM consensus_identity LIMIT ?1)",
        values_query: "SELECT COUNT(*), COALESCE(MAX(MAX(COALESCE(length(roster_attestation_root_id), 0), COALESCE(length(roster_attestation_public_key), 0), COALESCE(length(roster_attestation_algorithm_version), 0))), 0), COALESCE(SUM(COALESCE(length(roster_attestation_root_id), 0) + COALESCE(length(roster_attestation_public_key), 0) + COALESCE(length(roster_attestation_algorithm_version), 0)), 0) FROM (SELECT roster_attestation_root_id, roster_attestation_public_key, roster_attestation_algorithm_version FROM consensus_identity LIMIT ?1)",
        protocol_cap: 1,
        protocol_max_value: ProtectedRosterValueCap::Fixed(33),
    };
    const TABLES: &[ProtectedRosterPreflightTable] = &[
        ProtectedRosterPreflightTable {
            count_query: "SELECT COUNT(*) FROM (SELECT binding FROM consensus_protected_roster_rows LIMIT ?1)",
            values_query: "SELECT COUNT(*), COALESCE(MAX(MAX(length(binding), length(partition), COALESCE(length(terminalized_at), 0), length(canonical_record))), 0), COALESCE(SUM(length(binding) + length(partition) + COALESCE(length(terminalized_at), 0) + length(canonical_record)), 0) FROM (SELECT binding, partition, terminalized_at, canonical_record FROM consensus_protected_roster_rows LIMIT ?1)",
            protocol_cap: FENCED_MUTATION_ROSTER_MAX_RESERVED_AND_RETAINED,
            protocol_max_value: ProtectedRosterValueCap::CanonicalRecord,
        },
        ProtectedRosterPreflightTable {
            count_query: "SELECT COUNT(*) FROM (SELECT partition FROM consensus_protected_roster_floors LIMIT ?1)",
            values_query: "SELECT COUNT(*), COALESCE(MAX(MAX(length(partition), length(canonical_floor))), 0), COALESCE(SUM(length(partition) + length(canonical_floor)), 0) FROM (SELECT partition, canonical_floor FROM consensus_protected_roster_floors LIMIT ?1)",
            protocol_cap: FENCED_MUTATION_ROSTER_MAX_RESERVED_AND_RETAINED,
            protocol_max_value: ProtectedRosterValueCap::Fixed(128),
        },
        ProtectedRosterPreflightTable {
            count_query: "SELECT COUNT(*) FROM (SELECT partition FROM consensus_protected_roster_retirement_cursors LIMIT ?1)",
            values_query: "SELECT COUNT(*), COALESCE(MAX(MAX(length(partition), length(canonical_cursor))), 0), COALESCE(SUM(length(partition) + length(canonical_cursor)), 0) FROM (SELECT partition, canonical_cursor FROM consensus_protected_roster_retirement_cursors LIMIT ?1)",
            protocol_cap: FENCED_MUTATION_ROSTER_MAX_RESERVED_AND_RETAINED,
            protocol_max_value: ProtectedRosterValueCap::Fixed(256),
        },
        ProtectedRosterPreflightTable {
            count_query: "SELECT COUNT(*) FROM (SELECT singleton FROM consensus_protected_roster_witness LIMIT ?1)",
            values_query: "SELECT COUNT(*), COALESCE(MAX(length(canonical_witness)), 0), COALESCE(SUM(length(canonical_witness)), 0) FROM (SELECT canonical_witness FROM consensus_protected_roster_witness LIMIT ?1)",
            protocol_cap: 1,
            protocol_max_value: ProtectedRosterValueCap::Fixed(1_024),
        },
        ProtectedRosterPreflightTable {
            count_query: "SELECT COUNT(*) FROM (SELECT business_key FROM consensus_protected_roster_business LIMIT ?1)",
            values_query: "SELECT COUNT(*), COALESCE(MAX(MAX(length(business_key), length(binding), length(canonical_business))), 0), COALESCE(SUM(length(business_key) + length(binding) + length(canonical_business)), 0) FROM (SELECT business_key, binding, canonical_business FROM consensus_protected_roster_business LIMIT ?1)",
            protocol_cap: FENCED_MUTATION_ROSTER_MAX_LIVE_ROSTERS,
            protocol_max_value: ProtectedRosterValueCap::CanonicalBusiness,
        },
        ProtectedRosterPreflightTable {
            count_query: "SELECT COUNT(*) FROM (SELECT binding FROM consensus_protected_roster_admissions LIMIT ?1)",
            values_query: "SELECT COUNT(*), COALESCE(MAX(MAX(length(binding), length(stable_slot), length(admission_request_id), length(terminal_request_id), length(original_owner), length(original_acquired_at), length(original_expires_at))), 0), COALESCE(SUM(length(binding) + length(stable_slot) + length(admission_request_id) + length(terminal_request_id) + length(original_owner) + length(original_acquired_at) + length(original_expires_at)), 0) FROM (SELECT binding, stable_slot, admission_request_id, terminal_request_id, original_owner, original_acquired_at, original_expires_at FROM consensus_protected_roster_admissions LIMIT ?1)",
            protocol_cap: FENCED_MUTATION_ROSTER_MAX_RESERVED_AND_RETAINED,
            protocol_max_value: ProtectedRosterValueCap::Fixed(128),
        },
    ];

    let (canonical_record, canonical_business) = consensus::protected_roster_recovery_value_caps();
    preflight_protected_roster_table(
        conn,
        budget,
        total_bytes,
        ROOT,
        canonical_record,
        canonical_business,
    )?;
    for table in TABLES {
        preflight_protected_roster_table(
            conn,
            budget,
            total_bytes,
            *table,
            canonical_record,
            canonical_business,
        )?;
    }
    Ok(())
}

fn preflight_protected_roster_table(
    conn: &Connection,
    budget: &InspectionBudget,
    total_bytes: &mut u64,
    table: ProtectedRosterPreflightTable,
    canonical_record: usize,
    canonical_business: usize,
) -> Result<(), RecoveryError> {
    let probe_limit = i64::try_from(
        table
            .protocol_cap
            .checked_add(1)
            .ok_or(RecoveryError::CorruptReplica)?,
    )
    .map_err(|_| RecoveryError::CorruptReplica)?;
    let observed_count: i64 = conn
        .query_row(table.count_query, [probe_limit], |row| row.get(0))
        .map_err(|error| inspection_sql_error(error, budget))?;
    let observed_count =
        usize::try_from(observed_count).map_err(|_| RecoveryError::CorruptReplica)?;
    if observed_count > table.protocol_cap {
        return Err(RecoveryError::CorruptReplica);
    }

    let aggregate_limit =
        i64::try_from(table.protocol_cap).map_err(|_| RecoveryError::CorruptReplica)?;
    let (count, maximum, total): (i64, i64, i64) = conn
        .query_row(table.values_query, [aggregate_limit], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|error| inspection_sql_error(error, budget))?;
    let count = u64::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
    let maximum = u64::try_from(maximum).map_err(|_| RecoveryError::CorruptReplica)?;
    let total = u64::try_from(total).map_err(|_| RecoveryError::CorruptReplica)?;
    *total_bytes = total_bytes
        .checked_add(total)
        .ok_or(RecoveryError::WorkLimitExceeded)?;
    let protocol_max_value = match table.protocol_max_value {
        ProtectedRosterValueCap::Fixed(value) => value,
        ProtectedRosterValueCap::CanonicalRecord => canonical_record,
        ProtectedRosterValueCap::CanonicalBusiness => canonical_business,
    };
    if maximum > u64::try_from(protocol_max_value).map_err(|_| RecoveryError::CorruptReplica)? {
        return Err(RecoveryError::CorruptReplica);
    }
    if count > budget.limits.max_rows()
        || maximum > budget.limits.max_value_bytes()
        || *total_bytes > budget.limits.max_total_value_bytes()
    {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    Ok(())
}

/// Validate the complete V3 non-absorbing history state without repairing or
/// advancing it.  In particular, recovery never infers a retirement from a
/// missing row: doing so would make an offline inspection capable of erasing
/// or resurrecting V2 history.
fn validate_fenced_transition_v2_recovery_state(
    conn: &Connection,
    storage_identity: SessionConsensusIdentity,
) -> Result<(), RecoveryError> {
    preflight_fenced_transition_v2_receipt_count(conn)?;
    let storage_epoch = i64::try_from(storage_identity.configuration_epoch().get())
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let activation_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM consensus_fenced_transition_v2_activation",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if !(0..=1).contains(&activation_count) {
        return Err(RecoveryError::CorruptReplica);
    }
    if activation_count == 1 {
        let membership_scope = consensus::read_membership_scope_sync(conn, storage_identity)
            .map_err(|_| RecoveryError::CorruptReplica)?;
        let scope_matches = consensus::fenced_transition_v2_activation_matches_scope_sync(
            conn,
            storage_identity,
            membership_scope.current_identity,
            &membership_scope.current_members,
            crate::fenced_transition::fenced_transition_v2_profile_digest(),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
        if !scope_matches {
            return Err(RecoveryError::CorruptReplica);
        }
    }
    let rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM consensus_fenced_transition_v2_history",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if rows != 1 {
        return Err(RecoveryError::CorruptReplica);
    }
    let (
        history_storage_epoch,
        history_profile_digest,
        active_epoch,
        retired_through,
        generation,
        bound_count,
        reclaim_epoch,
        reclaim_cursor,
        reclaim_remaining,
        reclaimed_entries,
    ): FencedTransitionV2HistorySqlRow = conn
        .query_row(
            "SELECT storage_configuration_epoch, profile_digest, active_epoch, retired_through_epoch, generation, current_bound_count, reclaim_epoch, reclaim_cursor_ordinal, reclaim_remaining, reclaimed_entries FROM consensus_fenced_transition_v2_history WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?,
                ))
            },
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if history_storage_epoch != storage_epoch {
        return Err(RecoveryError::CorruptReplica);
    }
    let history_profile_digest: [u8; 32] = history_profile_digest
        .try_into()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if history_profile_digest != crate::fenced_transition::fenced_transition_v2_profile_digest() {
        return Err(RecoveryError::CorruptReplica);
    }
    let retired_through =
        u64::try_from(retired_through).map_err(|_| RecoveryError::CorruptReplica)?;
    let _generation = u64::try_from(generation).map_err(|_| RecoveryError::CorruptReplica)?;
    let bound_count = usize::try_from(bound_count).map_err(|_| RecoveryError::CorruptReplica)?;
    let _reclaimed_entries =
        u64::try_from(reclaimed_entries).map_err(|_| RecoveryError::CorruptReplica)?;
    if bound_count > FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES {
        return Err(RecoveryError::CorruptReplica);
    }
    let active_epoch = u64::try_from(active_epoch.ok_or(RecoveryError::CorruptReplica)?)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(RecoveryError::CorruptReplica)?;
    let reclaim_epoch = match reclaim_epoch {
        Some(value) => Some(
            u64::try_from(value)
                .ok()
                .filter(|value| *value != 0)
                .ok_or(RecoveryError::CorruptReplica)?,
        ),
        None => None,
    };
    let reclaim_cursor = reclaim_cursor
        .map(|value| u64::try_from(value).map_err(|_| RecoveryError::CorruptReplica))
        .transpose()?;
    let reclaim_remaining = reclaim_remaining
        .map(|value| usize::try_from(value).map_err(|_| RecoveryError::CorruptReplica))
        .transpose()?;
    let mut statement = conn
        .prepare(
            "SELECT request_id, history_epoch, ordinal, configuration_epoch, payload_digest, retained_until, binding_digest, response_json, response_digest FROM consensus_fenced_transition_v2_receipts ORDER BY history_epoch, ordinal, request_id",
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let mut receipt_rows = statement
        .query([])
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let mut receipts = Vec::with_capacity(bound_count);
    while let Some(row) = receipt_rows
        .next()
        .map_err(|_| RecoveryError::CorruptReplica)?
    {
        let request_id: Vec<u8> = row.get(0).map_err(|_| RecoveryError::CorruptReplica)?;
        let history_epoch: i64 = row.get(1).map_err(|_| RecoveryError::CorruptReplica)?;
        let ordinal: i64 = row.get(2).map_err(|_| RecoveryError::CorruptReplica)?;
        let configuration_epoch: i64 = row.get(3).map_err(|_| RecoveryError::CorruptReplica)?;
        let payload_digest: Vec<u8> = row.get(4).map_err(|_| RecoveryError::CorruptReplica)?;
        let retained_until: String = row.get(5).map_err(|_| RecoveryError::CorruptReplica)?;
        let binding_digest: Vec<u8> = row.get(6).map_err(|_| RecoveryError::CorruptReplica)?;
        let response: Option<Vec<u8>> = row.get(7).map_err(|_| RecoveryError::CorruptReplica)?;
        let response_digest: Option<Vec<u8>> =
            row.get(8).map_err(|_| RecoveryError::CorruptReplica)?;
        let history_epoch =
            u64::try_from(history_epoch).map_err(|_| RecoveryError::CorruptReplica)?;
        let ordinal = u64::try_from(ordinal).map_err(|_| RecoveryError::CorruptReplica)?;
        if history_epoch == 0
            || ordinal == 0
            || configuration_epoch != storage_epoch
            || request_id.len() != FENCED_TRANSITION_V2_REQUEST_ID_BYTES
            || payload_digest.len() != 32
            || binding_digest.len() != 32
            || retained_until.len() != consensus::FENCED_TRANSITION_RECEIPT_TIMESTAMP_BYTES
            || response.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > FENCED_TRANSITION_V2_RECEIPT_RESPONSE_MAX_BYTES
            })
            || match (&response, &response_digest) {
                (None, None) => false,
                (Some(_), Some(value)) if value.len() == 32 => false,
                _ => true,
            }
        {
            return Err(RecoveryError::CorruptReplica);
        }
        let request_id: [u8; FENCED_TRANSITION_V2_REQUEST_ID_BYTES] = request_id
            .try_into()
            .map_err(|_| RecoveryError::CorruptReplica)?;
        let request_epoch = u64::from_be_bytes(
            request_id[..8]
                .try_into()
                .map_err(|_| RecoveryError::CorruptReplica)?,
        );
        if request_epoch != history_epoch {
            return Err(RecoveryError::CorruptReplica);
        }
        let timestamp =
            Timestamp::from_str(&retained_until).map_err(|_| RecoveryError::CorruptReplica)?;
        if ops::format_rfc3339_normalized(timestamp) != retained_until {
            return Err(RecoveryError::CorruptReplica);
        }
        let payload_digest: [u8; 32] = payload_digest
            .try_into()
            .map_err(|_| RecoveryError::CorruptReplica)?;
        if payload_digest
            != consensus::fenced_transition_v2_payload_digest_for_request_id(
                storage_identity,
                request_id,
            )
            .map_err(|_| RecoveryError::CorruptReplica)?
        {
            return Err(RecoveryError::CorruptReplica);
        }
        let expected_binding = consensus::fenced_transition_v2_receipt_binding_digest(
            storage_identity,
            request_id,
            history_epoch,
            ordinal,
            payload_digest,
            &retained_until,
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
        let binding_digest: [u8; 32] = binding_digest
            .try_into()
            .map_err(|_| RecoveryError::CorruptReplica)?;
        if binding_digest != expected_binding {
            return Err(RecoveryError::CorruptReplica);
        }
        if let (Some(response), Some(response_digest)) = (response, response_digest) {
            consensus::decode_fenced_transition_v2_response(&response)
                .map_err(|_| RecoveryError::CorruptReplica)?;
            let response_digest: [u8; 32] = response_digest
                .try_into()
                .map_err(|_| RecoveryError::CorruptReplica)?;
            if response_digest
                != consensus::fenced_transition_v2_receipt_response_digest(
                    expected_binding,
                    &response,
                )
                .map_err(|_| RecoveryError::CorruptReplica)?
            {
                return Err(RecoveryError::CorruptReplica);
            }
        }
        receipts.push((history_epoch, ordinal));
    }
    drop(receipt_rows);
    drop(statement);

    let maximum_history_entries = u64::try_from(FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let retained_epochs = active_epoch.checked_sub(retired_through);
    let reclaiming = match (reclaim_epoch, reclaim_cursor, reclaim_remaining) {
        (None, None, None) => {
            if !retained_epochs.is_some_and(|count| {
                (1..=u64::try_from(FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS + 1).unwrap_or(u64::MAX))
                    .contains(&count)
            }) {
                return Err(RecoveryError::CorruptReplica);
            }
            false
        }
        (Some(reclaim), Some(cursor), Some(remaining)) => {
            if reclaim != retired_through
                || !retained_epochs.is_some_and(|count| {
                    (1..=u64::try_from(FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS).unwrap_or(u64::MAX))
                        .contains(&count)
                })
                || !(1..=FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES).contains(&remaining)
                || cursor.checked_add(
                    u64::try_from(remaining).map_err(|_| RecoveryError::CorruptReplica)?,
                ) != Some(maximum_history_entries)
            {
                return Err(RecoveryError::CorruptReplica);
            }
            true
        }
        _ => return Err(RecoveryError::CorruptReplica),
    };
    let minimum_epoch = if reclaiming {
        retired_through
    } else {
        retired_through
            .checked_add(1)
            .ok_or(RecoveryError::CorruptReplica)?
    };
    let mut epoch_counts = BTreeMap::<u64, usize>::new();
    let mut previous_ordinals = BTreeMap::<u64, u64>::new();
    for (epoch, ordinal) in receipts {
        if !(minimum_epoch..=active_epoch).contains(&epoch) {
            return Err(RecoveryError::CorruptReplica);
        }
        let expected_ordinal = previous_ordinals
            .get(&epoch)
            .copied()
            .unwrap_or_else(|| {
                if reclaim_epoch == Some(epoch) {
                    reclaim_cursor.unwrap_or(0)
                } else {
                    0
                }
            })
            .checked_add(1)
            .ok_or(RecoveryError::CorruptReplica)?;
        if ordinal != expected_ordinal {
            return Err(RecoveryError::CorruptReplica);
        }
        previous_ordinals.insert(epoch, ordinal);
        let count = epoch_counts.entry(epoch).or_default();
        *count = count.checked_add(1).ok_or(RecoveryError::CorruptReplica)?;
        if *count > FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES {
            return Err(RecoveryError::CorruptReplica);
        }
    }
    if epoch_counts.get(&active_epoch).copied().unwrap_or(0) != bound_count {
        return Err(RecoveryError::CorruptReplica);
    }
    for epoch in minimum_epoch..=active_epoch {
        let count = epoch_counts.get(&epoch).copied().unwrap_or(0);
        if !consensus::fenced_transition_v2_closed_epoch_is_exact(
            epoch,
            active_epoch,
            reclaim_epoch,
            reclaim_cursor,
            reclaim_remaining
                .map(|remaining| {
                    u64::try_from(remaining).map_err(|_| RecoveryError::CorruptReplica)
                })
                .transpose()?,
            count,
        ) {
            return Err(RecoveryError::CorruptReplica);
        }
    }
    consensus::validate_fenced_transition_v2_receipts_sync(conn, storage_identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    Ok(())
}

/// How the selected snapshot participates in the authenticated committed
/// branch.  A snapshot that merely coexists with a complete retained suffix
/// is local compaction state and is deliberately not propagated.  In contrast,
/// a snapshot immediately preceding the first physical row with no purge
/// floor is the durable prefix of that suffix and must travel with it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CurrentSnapshotBranchRole {
    Redundant,
    Boundary,
    CommittedFallback,
}

fn current_snapshot_branch_role(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    committed: Option<&LogId<SessionConsensusNodeId>>,
    purged: Option<&LogId<SessionConsensusNodeId>>,
    snapshot_log: Option<&LogId<SessionConsensusNodeId>>,
) -> Result<CurrentSnapshotBranchRole, RecoveryError> {
    let Some(committed) = committed else {
        return Ok(CurrentSnapshotBranchRole::Redundant);
    };
    let end = committed
        .index
        .checked_add(1)
        .ok_or(RecoveryError::CorruptReplica)?;
    let committed_row = consensus::read_log_range_for_recovery_sync(
        conn,
        identity,
        committed.index,
        Some(end),
        Some(1),
    )
    .map_err(|_| RecoveryError::CorruptReplica)?;
    match committed_row.as_slice() {
        [entry] if entry.log_id == *committed => {}
        [] if purged == Some(committed) => return Ok(CurrentSnapshotBranchRole::Redundant),
        [] if snapshot_log == Some(committed) => {
            return Ok(CurrentSnapshotBranchRole::CommittedFallback);
        }
        [] => return Err(RecoveryError::CorruptReplica),
        _ => return Err(RecoveryError::CorruptReplica),
    }
    if purged.is_some() {
        return Ok(CurrentSnapshotBranchRole::Redundant);
    }

    // With no purge floor, the sole supported omitted initial prefix is a
    // selected snapshot immediately followed by the first physical row.
    // Keep that snapshot as branch authority; it is the retained suffix's
    // durable predecessor rather than a source-local historical artifact.
    let first =
        consensus::read_physical_log_range_for_recovery_sync(conn, identity, 0, None, Some(1))
            .map_err(|_| RecoveryError::CorruptReplica)?;
    match (snapshot_log, first.as_slice()) {
        (Some(snapshot), [entry])
            if entry.log_id.index
                == snapshot
                    .index
                    .checked_add(1)
                    .ok_or(RecoveryError::CorruptReplica)? =>
        {
            Ok(CurrentSnapshotBranchRole::Boundary)
        }
        _ => Ok(CurrentSnapshotBranchRole::Redundant),
    }
}

fn hash_current_snapshot_branch_authority(
    hasher: &mut Sha256,
    snapshot: &consensus::CurrentSnapshot,
    snapshot_dir: &Path,
    budget: &mut InspectionBudget,
    snapshot_file: Option<&mut PinnedSnapshotFile>,
) -> Result<(), RecoveryError> {
    let snapshot_path = snapshot_dir.join(&snapshot.1);
    let observed = if let Some(file) = snapshot_file {
        file.verify_path_identity(&snapshot_path)?;
        let observed =
            verify_pinned_snapshot_file(file, budget.limits.max_snapshot_bytes(), Some(budget))?;
        file.verify_path_identity(&snapshot_path)?;
        observed
    } else {
        verify_snapshot_file(
            &snapshot_path,
            budget.limits.max_snapshot_bytes(),
            Some(budget),
        )?
    };
    if observed.0 != snapshot.2 || observed.1 != snapshot.3 {
        return Err(RecoveryError::CorruptReplica);
    }
    hasher.update(snapshot.2);
    hasher.update(snapshot.3.to_be_bytes());
    feed_json(hasher, &snapshot.0)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn committed_branch_digest(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    committed: Option<&LogId<SessionConsensusNodeId>>,
    snapshot_dir: &Path,
    budget: &mut InspectionBudget,
    recovery_epoch: u64,
    last_plan_digest: [u8; 32],
    pending_epoch: Option<u64>,
    pending_plan_digest: Option<[u8; 32]>,
    watch_cursor_invalidation_floor: u64,
    authority_profile: RecoveryAuthorityProfile,
    fixed_placement_policy: Option<RecoveryFixedPlacementPolicy>,
    protected_roster_digest: RecoveryDigest,
    snapshot_file: Option<&mut PinnedSnapshotFile>,
) -> Result<RecoveryDigest, RecoveryError> {
    let mut hasher = Sha256::new();
    hasher.update(CURRENT_BRANCH_DOMAIN);
    hasher.update(identity.cluster_id().as_bytes());
    hasher.update(identity.configuration_id().as_bytes());
    hasher.update(identity.configuration_epoch().get().to_be_bytes());
    hasher.update(recovery_epoch.to_be_bytes());
    hasher.update(last_plan_digest);
    hasher.update(watch_cursor_invalidation_floor.to_be_bytes());
    hash_recovery_authority_descriptor(&mut hasher, authority_profile, fixed_placement_policy)?;
    hasher.update(PROTECTED_ROSTER_DIGEST_DOMAIN);
    hasher.update(protected_roster_digest.as_bytes());
    match (pending_epoch, pending_plan_digest) {
        (Some(epoch), Some(digest)) => {
            hasher.update([1]);
            hasher.update(epoch.to_be_bytes());
            hasher.update(digest);
        }
        (None, None) => hasher.update([0]),
        _ => return Err(RecoveryError::CorruptReplica),
    }
    let Some(committed) = committed else {
        hasher.update([0]);
        hash_current_checkpoint(conn, budget, &mut hasher, protected_roster_digest)?;
        return Ok(RecoveryDigest::from_bytes(hasher.finalize().into()));
    };
    hasher.update([1]);
    feed_json(&mut hasher, committed)?;

    let purged =
        consensus::read_purged_sync(conn, identity).map_err(|_| RecoveryError::CorruptReplica)?;
    // A purge floor is a full Raft log identity, not merely an index used to
    // choose the first physical row.  The exact term/leader is durable branch
    // authority: two replicas with the same suffix above one index but
    // different purged LogIds must never compare as a recovery majority.
    match purged.as_ref() {
        Some(log_id) => {
            hasher.update([1]);
            feed_json(&mut hasher, log_id)?;
        }
        None => hasher.update([0]),
    }
    let snapshot = consensus::read_current_snapshot_sync(conn, identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let snapshot_log = snapshot
        .as_ref()
        .and_then(|(meta, _, _, _)| meta.last_log_id.as_ref());
    let end = committed
        .index
        .checked_add(1)
        .ok_or(RecoveryError::CorruptReplica)?;
    let max_rows =
        usize::try_from(budget.limits.max_rows()).map_err(|_| RecoveryError::WorkLimitExceeded)?;

    let snapshot_role = current_snapshot_branch_role(
        conn,
        identity,
        Some(committed),
        purged.as_ref(),
        snapshot_log,
    )?;
    let (suffix_start, suffix_end, requires_committed_row) = match snapshot_role {
        CurrentSnapshotBranchRole::CommittedFallback => {
            let snapshot = snapshot.as_ref().ok_or(RecoveryError::CorruptReplica)?;
            hasher.update([2]);
            hash_current_snapshot_branch_authority(
                &mut hasher,
                snapshot,
                snapshot_dir,
                budget,
                snapshot_file,
            )?;
            // A snapshot covering the missing committed record is terminal
            // authority, not a license to hide its still-physical prefix.
            // Bind every retained row below that fallback so different valid
            // histories cannot compare as one recovery branch.
            (
                purged
                    .as_ref()
                    .map(|log_id| {
                        log_id
                            .index
                            .checked_add(1)
                            .ok_or(RecoveryError::CorruptReplica)
                    })
                    .transpose()?
                    .unwrap_or(0),
                committed.index,
                false,
            )
        }
        CurrentSnapshotBranchRole::Boundary => {
            let snapshot = snapshot.as_ref().ok_or(RecoveryError::CorruptReplica)?;
            let snapshot_log = snapshot
                .0
                .last_log_id
                .as_ref()
                .ok_or(RecoveryError::CorruptReplica)?;
            hasher.update([3]);
            hash_current_snapshot_branch_authority(
                &mut hasher,
                snapshot,
                snapshot_dir,
                budget,
                snapshot_file,
            )?;
            (
                snapshot_log
                    .index
                    .checked_add(1)
                    .ok_or(RecoveryError::CorruptReplica)?,
                end,
                true,
            )
        }
        // A complete retained branch is authoritative beginning exactly after
        // its durable purge marker (or at zero).  A selected historical
        // snapshot in this shape stays digest-neutral and is omitted by
        // staging, while every retained prefix row remains quorum evidence.
        CurrentSnapshotBranchRole::Redundant => (
            purged
                .as_ref()
                .map(|log_id| {
                    log_id
                        .index
                        .checked_add(1)
                        .ok_or(RecoveryError::CorruptReplica)
                })
                .transpose()?
                .unwrap_or(0),
            end,
            true,
        ),
    };
    let entries = if suffix_start < suffix_end {
        consensus::read_log_range_for_recovery_sync(
            conn,
            identity,
            suffix_start,
            Some(suffix_end),
            Some(max_rows),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?
    } else {
        Vec::new()
    };
    if entries.len() > max_rows {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    let mut expected_index = suffix_start;
    for entry in &entries {
        if entry.log_id.index != expected_index || entry.log_id.index >= suffix_end {
            return Err(RecoveryError::CorruptReplica);
        }
        expected_index = expected_index
            .checked_add(1)
            .ok_or(RecoveryError::CorruptReplica)?;
    }
    if requires_committed_row
        && suffix_start <= committed.index
        && entries.last().map(|entry| entry.log_id) != Some(*committed)
    {
        return Err(RecoveryError::CorruptReplica);
    }
    hasher.update([1]);
    hasher.update(
        u64::try_from(entries.len())
            .map_err(|_| RecoveryError::WorkLimitExceeded)?
            .to_be_bytes(),
    );
    for entry in &entries {
        feed_json(&mut hasher, entry)?;
    }
    hash_current_checkpoint(conn, budget, &mut hasher, protected_roster_digest)?;
    Ok(RecoveryDigest::from_bytes(hasher.finalize().into()))
}

fn hash_current_checkpoint(
    conn: &Connection,
    budget: &mut InspectionBudget,
    hasher: &mut Sha256,
    protected_roster_digest: RecoveryDigest,
) -> Result<(), RecoveryError> {
    // Compatibility state is consensus evidence, not incidental SQLite
    // layout.  In particular, two otherwise identical checkpoints whose V2
    // activation certificate differs must never compare as one recoverable
    // branch.
    let receipt_layout = consensus::fenced_transition_receipt_ledger_layout_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let v2_ledger_layout = consensus::fenced_transition_v2_ledger_layout_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let (cluster, configuration, epoch): (Vec<u8>, Vec<u8>, i64) = conn
        .query_row(
            "SELECT cluster_id, configuration_id, configuration_epoch FROM consensus_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let cluster: [u8; 32] = cluster
        .try_into()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let configuration: [u8; 32] = configuration
        .try_into()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let epoch = u64::try_from(epoch)
        .ok()
        .and_then(|value| SessionConsensusConfigurationEpoch::new(value).ok())
        .ok_or(RecoveryError::CorruptReplica)?;
    let storage_identity = SessionConsensusIdentity::new(
        crate::consensus::SessionConsensusClusterId::from_bytes(cluster),
        SessionConsensusConfigurationId::from_bytes(configuration),
        epoch,
    );
    if v2_ledger_layout == consensus::FencedTransitionV2LedgerLayout::Activated {
        validate_fenced_transition_v2_recovery_state(conn, storage_identity)?;
    }
    hasher.update(b"openpacketcore/session-recovery/fenced-transition-layout/v1\0");
    // An exact #684 predecessor and an empty Prepared layout carry the same
    // state-machine semantics: neither can serve V1 and a writable reopen
    // may prepare the latter without a consensus command. Keep those
    // checkpoints recoverably equivalent during a rolling upgrade. Activated
    // is deliberately distinct because its schema fence rejects an old
    // reader and its optional current-scope certificate changes V1 authority.
    hasher.update(match receipt_layout {
        consensus::FencedTransitionReceiptLedgerLayout::Published684
        | consensus::FencedTransitionReceiptLedgerLayout::Prepared => [0],
        consensus::FencedTransitionReceiptLedgerLayout::Activated => [1],
    });
    hasher.update(b"openpacketcore/session-recovery/fenced-transition-v2-layout/v1\0");
    hasher.update(match v2_ledger_layout {
        consensus::FencedTransitionV2LedgerLayout::Absent => [0],
        consensus::FencedTransitionV2LedgerLayout::Activated => [1],
    });
    // The roster projection has its own canonical evidence digest.  Feeding
    // that authenticated digest here prevents the branch commitment and the
    // post-staging checks from drifting apart as activated roster tables grow.
    hasher.update(PROTECTED_ROSTER_DIGEST_DOMAIN);
    hasher.update(protected_roster_digest.as_bytes());
    let schema_version: i64 = conn
        .query_row(
            "SELECT schema_version FROM consensus_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    hasher.update(schema_version.to_be_bytes());
    if receipt_layout == consensus::FencedTransitionReceiptLedgerLayout::Activated
        && table_exists(conn, "consensus_fenced_transition_activation")?
    {
        let query = "SELECT * FROM consensus_fenced_transition_activation ORDER BY singleton";
        hash_query_rows_with_identity(conn, query, query, budget, hasher)?;
    }
    if v2_ledger_layout == consensus::FencedTransitionV2LedgerLayout::Activated {
        for query in [
            "SELECT * FROM consensus_fenced_transition_v2_history ORDER BY singleton",
            "SELECT * FROM consensus_fenced_transition_v2_activation ORDER BY singleton",
            "SELECT * FROM consensus_fenced_transition_v2_receipts ORDER BY history_epoch, ordinal, request_id",
        ] {
            hash_query_rows_with_identity(conn, query, query, budget, hasher)?;
        }
    }
    let records_query =
        "SELECT * FROM session_records ORDER BY tenant, nf_kind, key_type, stable_id";
    hash_query_rows_with_identity(conn, records_query, records_query, budget, hasher)?;
    hash_legacy_lease_rows(conn, budget, hasher)?;
    for query in [
        "SELECT * FROM key_fences ORDER BY tenant, nf_kind, key_type, stable_id",
        "SELECT * FROM lease_globals ORDER BY key",
        "SELECT * FROM session_replication_log ORDER BY sequence",
        "SELECT * FROM consensus_machine ORDER BY singleton",
        "SELECT * FROM consensus_membership ORDER BY singleton",
        "SELECT * FROM consensus_applied ORDER BY singleton",
        "SELECT * FROM consensus_request_outcomes ORDER BY request_id",
    ] {
        hash_query_rows_with_identity(conn, query, query, budget, hasher)?;
    }
    let fenced_receipts_query =
        "SELECT * FROM consensus_fenced_transition_receipts ORDER BY request_id";
    if table_exists(conn, "consensus_fenced_transition_receipts")?
        && preflight_fenced_transition_receipt_count(conn)? != 0
    {
        consensus::validate_fenced_transition_receipt_storage_bounds_sync(conn)
            .map_err(|_| RecoveryError::CorruptReplica)?;
        hash_query_rows_with_identity(
            conn,
            fenced_receipts_query,
            fenced_receipts_query,
            budget,
            hasher,
        )?;
    }
    if table_exists(conn, "consensus_membership_scope")? {
        let query = "SELECT * FROM consensus_membership_scope ORDER BY singleton";
        hash_query_rows_with_identity(conn, query, query, budget, hasher)?;
    }
    if table_exists(conn, "consensus_membership_history")? {
        let query = "SELECT * FROM consensus_membership_history ORDER BY configuration_epoch";
        hash_query_rows_with_identity(conn, query, query, budget, hasher)?;
    }
    let terminal_history_query = "SELECT * FROM consensus_membership_terminal_history ORDER BY transition_start_index, transition_id";
    hasher.update(
        u64::try_from(terminal_history_query.len())
            .map_err(|_| RecoveryError::WorkLimitExceeded)?
            .to_be_bytes(),
    );
    hasher.update(terminal_history_query.as_bytes());
    if table_exists(conn, "consensus_membership_terminal_history")? {
        hash_query_rows(conn, terminal_history_query, budget, hasher)?;
    }
    Ok(())
}

/// Hash the protected-roster evidence in the one canonical representation
/// used by both branch selection and post-copy verification.  A Prepared
/// namespace remains equivalent to its exact rootless predecessor, but an
/// activated namespace commits its verifier root and every projection.
fn protected_roster_digest(
    conn: &Connection,
    budget: &mut InspectionBudget,
) -> Result<RecoveryDigest, RecoveryError> {
    let layout = consensus::protected_roster_recovery_layout_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let (cluster, configuration, epoch): (Vec<u8>, Vec<u8>, i64) = conn
        .query_row(
            "SELECT cluster_id, configuration_id, configuration_epoch FROM consensus_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let cluster: [u8; 32] = cluster
        .try_into()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let configuration: [u8; 32] = configuration
        .try_into()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let epoch = u64::try_from(epoch)
        .ok()
        .and_then(|value| SessionConsensusConfigurationEpoch::new(value).ok())
        .ok_or(RecoveryError::CorruptReplica)?;
    let identity = SessionConsensusIdentity::new(
        crate::consensus::SessionConsensusClusterId::from_bytes(cluster),
        SessionConsensusConfigurationId::from_bytes(configuration),
        epoch,
    );
    let mut total_bytes = 0;
    preflight_protected_roster_tables(conn, budget, &mut total_bytes)?;
    consensus::validate_protected_roster_recovery_state_sync(conn, identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;

    let mut hasher = Sha256::new();
    hasher.update(PROTECTED_ROSTER_DIGEST_DOMAIN);
    hasher.update(PROTECTED_ROSTER_LAYOUT_DOMAIN);
    hasher.update(match layout {
        consensus::ProtectedRosterRecoveryLayout::Legacy
        | consensus::ProtectedRosterRecoveryLayout::Prepared => [0],
        consensus::ProtectedRosterRecoveryLayout::Activated => [1],
    });
    hasher.update(PROTECTED_ROSTER_TRUST_ROOT_DOMAIN);
    match consensus::protected_roster_recovery_trust_root_commitment_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?
    {
        None => hasher.update([0]),
        Some(commitment) => {
            hasher.update([1]);
            hasher.update(commitment);
        }
    }
    if layout == consensus::ProtectedRosterRecoveryLayout::Activated {
        for query in [
            "SELECT * FROM consensus_protected_roster_rows ORDER BY binding",
            "SELECT * FROM consensus_protected_roster_floors ORDER BY partition",
            "SELECT * FROM consensus_protected_roster_retirement_cursors ORDER BY partition",
            "SELECT * FROM consensus_protected_roster_witness ORDER BY singleton",
            "SELECT * FROM consensus_protected_roster_business ORDER BY business_key",
            "SELECT * FROM consensus_protected_roster_admissions ORDER BY binding",
        ] {
            hash_query_rows_with_identity(conn, query, query, budget, &mut hasher)?;
        }
    }
    Ok(RecoveryDigest::from_bytes(hasher.finalize().into()))
}

fn hash_recovery_authority_descriptor(
    hasher: &mut Sha256,
    profile: RecoveryAuthorityProfile,
    fixed_placement_policy: Option<RecoveryFixedPlacementPolicy>,
) -> Result<(), RecoveryError> {
    hasher.update(AUTHORITY_DESCRIPTOR_DOMAIN);
    match (profile, fixed_placement_policy) {
        (RecoveryAuthorityProfile::Dynamic, None) => hasher.update([1, 0]),
        (
            RecoveryAuthorityProfile::FixedImmutable,
            Some(RecoveryFixedPlacementPolicy::RequireIndependentFailureDomains),
        ) => hasher.update([2, 1]),
        (
            RecoveryAuthorityProfile::FixedImmutable,
            Some(RecoveryFixedPlacementPolicy::AllowReducedResilience),
        ) => hasher.update([2, 2]),
        _ => return Err(RecoveryError::CorruptReplica),
    }
    Ok(())
}

fn inspect_legacy(
    input: InspectionInput<'_>,
    conn: &Connection,
    path_binding: RecoveryDigest,
    file_identity: RecoveryDigest,
    budget: &mut InspectionBudget,
) -> Result<RecoveryReplicaEvidence, RecoveryError> {
    validate_legacy_schema(conn)?;
    validate_consensus_sealed_records(conn, budget)?;
    validate_legacy_lease_state(conn, budget)?;
    validate_replication_sequence_domain(conn, budget, 0)?;
    let branch_digest = hash_legacy_state(conn, budget)?;
    let fence_high_water = consensus::observed_fence_high_water_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let credential_high_water = consensus::observed_credential_high_water_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let logical_state_digest = hash_logical_state(conn, budget)?;
    let recovery_v2_invariant_state_digest = hash_recovery_v2_invariant_state(conn, budget)?;
    budget.check()?;
    let local_head_index: Option<i64> = conn
        .query_row(
            "SELECT MAX(sequence) FROM session_replication_log",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let local_head_index = local_head_index
        .map(u64::try_from)
        .transpose()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let sequence_high_water = local_head_index.unwrap_or(0);
    Ok(RecoveryReplicaEvidence {
        replica_token: super::replica_token(input.key, &input.replica.replica_id)?,
        backing_identity: RecoveryDigest::from_bytes(input.replica.backing_identity.fingerprint()),
        path_binding,
        file_identity,
        format: RecoveryReplicaFormat::LegacyUnproven,
        cluster_digest: None,
        configuration_digest: None,
        configuration_epoch: None,
        // Pre-consensus replicas cannot be fixed immutable: that authority
        // profile was introduced with the consensus identity table.  Legacy
        // recovery remains explicit/unproven and can only carry the dynamic
        // transport shape, never an inferred fixed policy.
        authority_profile: RecoveryAuthorityProfile::Dynamic,
        fixed_placement_policy: None,
        current_snapshot_identity: None,
        recovery_epoch: 0,
        last_plan_digest: RecoveryDigest::from_bytes([0; 32]),
        pending_recovery_epoch: None,
        pending_plan_digest: None,
        finalize_log_id: None,
        watch_cursor_invalidation_floor: 0,
        application_sequence: sequence_high_water,
        machine_last_digest: RecoveryDigest::from_bytes([0; 32]),
        machine_logical_time: None,
        watch_sequence: sequence_high_water,
        authority_commitment: RecoveryDigest::from_bytes([0; 32]),
        committed_log_id: None,
        predecessor_bootstrap_membership_digest: None,
        applied_log_id: None,
        local_head_log_id: None,
        committed_index: None,
        applied_index: None,
        local_head_index,
        branch_digest,
        fence_high_water,
        credential_high_water,
        logical_state_digest,
        recovery_v2_invariant_state_digest,
        protected_roster_digest: legacy_protected_roster_digest(),
    })
}

fn legacy_protected_roster_digest() -> RecoveryDigest {
    let mut hasher = Sha256::new();
    hasher.update(PROTECTED_ROSTER_DIGEST_DOMAIN);
    hasher.update(PROTECTED_ROSTER_LAYOUT_DOMAIN);
    hasher.update([0]);
    hasher.update(PROTECTED_ROSTER_TRUST_ROOT_DOMAIN);
    hasher.update([0]);
    RecoveryDigest::from_bytes(hasher.finalize().into())
}

fn validate_legacy_schema(conn: &Connection) -> Result<(), RecoveryError> {
    for (table, expected) in [
        (
            "session_records",
            &[
                "tenant",
                "nf_kind",
                "key_type",
                "stable_id",
                "generation",
                "owner",
                "fence",
                "state_class",
                "state_type",
                "expires_at",
                "payload",
                "encoding",
            ][..],
        ),
        ("leases", LEGACY_LEASE_COLUMNS_WITH_ACQUIRED_AT),
        (
            "key_fences",
            &["tenant", "nf_kind", "key_type", "stable_id", "fence"][..],
        ),
        ("lease_globals", &["key", "val"][..]),
        (
            "session_replication_log",
            &["sequence", "tx_id", "entry_json", "timestamp"][..],
        ),
    ] {
        let mut statement = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(|_| RecoveryError::CorruptReplica)?;
        let observed = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|_| RecoveryError::CorruptReplica)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RecoveryError::CorruptReplica)?;
        if (table == "leases"
            && observed != LEGACY_LEASE_COLUMNS_WITH_ACQUIRED_AT
            && observed != LEGACY_LEASE_COLUMNS_BEFORE_ACQUIRED_AT)
            || (table != "leases" && observed != expected)
        {
            return Err(RecoveryError::CorruptReplica);
        }
    }
    let has_restore_scan_state = validate_restore_scan_schema_if_present(conn)?;
    let mut expected = BTreeSet::from([
        "key_fences".to_string(),
        "lease_globals".to_string(),
        "leases".to_string(),
        "session_records".to_string(),
        "session_replication_log".to_string(),
    ]);
    if has_restore_scan_state {
        expected.insert("restore_scan_state".to_string());
    }
    let mut statement = conn
        .prepare(
            "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let objects = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| RecoveryError::CorruptReplica)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if objects.len() != expected.len()
        || objects
            .iter()
            .any(|(kind, name)| kind != "table" || !expected.contains(name))
    {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok(())
}

fn legacy_lease_has_acquired_at(conn: &Connection) -> Result<bool, RecoveryError> {
    let mut statement = conn
        .prepare("PRAGMA table_info(leases)")
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|_| RecoveryError::CorruptReplica)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if columns == LEGACY_LEASE_COLUMNS_WITH_ACQUIRED_AT {
        Ok(true)
    } else if columns == LEGACY_LEASE_COLUMNS_BEFORE_ACQUIRED_AT {
        Ok(false)
    } else {
        Err(RecoveryError::CorruptReplica)
    }
}

fn validate_restore_scan_schema_if_present(conn: &Connection) -> Result<bool, RecoveryError> {
    if !table_exists(conn, "restore_scan_state")? {
        return Ok(false);
    }
    let mut statement = conn
        .prepare("PRAGMA table_info(restore_scan_state)")
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let observed = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(|_| RecoveryError::CorruptReplica)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let legacy = vec![
        (
            0,
            "singleton".to_string(),
            "INTEGER".to_string(),
            0,
            None,
            1,
        ),
        (1, "epoch".to_string(), "BLOB".to_string(), 1, None, 0),
        (2, "revision".to_string(), "INTEGER".to_string(), 1, None, 0),
    ];
    let mut migrated = legacy.clone();
    migrated.push((3, "cursor_key".to_string(), "BLOB".to_string(), 0, None, 0));
    let mut current = legacy.clone();
    current.push((3, "cursor_key".to_string(), "BLOB".to_string(), 1, None, 0));
    let sql: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'restore_scan_state'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let normalized_sql = normalize_schema_sql(&sql);
    let expected_sql = if observed == legacy {
        normalize_schema_sql(
            r#"
            CREATE TABLE restore_scan_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                epoch BLOB NOT NULL CHECK (length(epoch) = 16),
                revision INTEGER NOT NULL CHECK (revision >= 0)
            )
            "#,
        )
    } else if observed == migrated {
        normalize_schema_sql(
            r#"
            CREATE TABLE restore_scan_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                epoch BLOB NOT NULL CHECK (length(epoch) = 16),
                revision INTEGER NOT NULL CHECK (revision >= 0),
                cursor_key BLOB CHECK (
                    cursor_key IS NULL OR length(cursor_key) = 32
                )
            )
            "#,
        )
    } else if observed == current {
        normalize_schema_sql(
            r#"
            CREATE TABLE restore_scan_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                epoch BLOB NOT NULL CHECK (length(epoch) = 16),
                revision INTEGER NOT NULL CHECK (revision >= 0),
                cursor_key BLOB NOT NULL CHECK (length(cursor_key) = 32)
            )
            "#,
        )
    } else {
        return Err(RecoveryError::CorruptReplica);
    };
    if normalized_sql != expected_sql {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok(true)
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_ascii_whitespace())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn ensure_restore_scan_metadata(conn: &Connection) -> Result<(), RecoveryError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS restore_scan_state (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            epoch BLOB NOT NULL CHECK (length(epoch) = 16),
            revision INTEGER NOT NULL CHECK (revision >= 0)
        );
        "#,
    )
    .map_err(|_| RecoveryError::FileOperationFailed)?;
    ops::initialize_restore_scan_metadata_sync(conn).map_err(|_| RecoveryError::FileOperationFailed)
}

fn validate_exact_recovery_schema(
    conn: &Connection,
    require_recovery_table: bool,
) -> Result<(), RecoveryError> {
    let v2_ledger_layout = consensus::fenced_transition_v2_ledger_layout_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let receipt_ledger_layout = consensus::fenced_transition_receipt_ledger_layout_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let protected_roster_layout = consensus::protected_roster_recovery_layout_sync(conn)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if receipt_ledger_layout == consensus::FencedTransitionReceiptLedgerLayout::Published684 {
        // The classifier compared the complete released manifest.  Its absent
        // ledger is canonically an empty ledger for recovery hashing. A
        // roster namespace or root identity cannot be silently appended to
        // this released format: the roster classifier must prove the exact
        // rootless predecessor before this compatibility return.
        if protected_roster_layout != consensus::ProtectedRosterRecoveryLayout::Legacy {
            return Err(RecoveryError::CorruptReplica);
        }
        return Ok(());
    }
    let has_restore_scan_state = validate_restore_scan_schema_if_present(conn)?;
    let canonical = crate::sqlite::SqliteSessionBackend::canonical_schema_connection()
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    consensus::install_recovery_validation_schema_sync(&canonical, false)
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    let mut expected = recovery_schema_manifest(&canonical)?;
    // Identity DDL and every protected-roster object have already passed the
    // bounded exact classifiers above. Excluding those objects here avoids
    // synthesizing one preferred ALTER-column order and accidentally rejecting
    // another exact emitted form; no persisted database is mutated for
    // recovery validation.
    expected
        .remove("consensus_identity")
        .ok_or(RecoveryError::DatabaseUnavailable)?;
    // `recovery_schema_manifest` validates every allowed index in place and
    // retains only table DDL in the returned map. The three roster indexes
    // therefore must not be removed a second time here.
    const PROTECTED_ROSTER_SCHEMA_TABLES: &[&str] = &[
        "consensus_protected_roster_rows",
        "consensus_protected_roster_floors",
        "consensus_protected_roster_retirement_cursors",
        "consensus_protected_roster_witness",
        "consensus_protected_roster_business",
        "consensus_protected_roster_admissions",
    ];
    for table in PROTECTED_ROSTER_SCHEMA_TABLES {
        // The canonical helper currently emits the pre-roster base and may
        // gain the additive namespace later. Its exact roster DDL is owned by
        // the classifier either way, so exclude it when present.
        expected.remove(*table);
    }
    let canonical_lease = expected
        .remove("leases")
        .ok_or(RecoveryError::DatabaseUnavailable)?;
    let legacy_canonical = crate::sqlite::SqliteSessionBackend::canonical_schema_connection()
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    legacy_canonical
        .execute_batch("ALTER TABLE leases DROP COLUMN acquired_at")
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    let pre_acquisition_timestamp_lease = schema_object_sql(&legacy_canonical, "leases")?
        .ok_or(RecoveryError::DatabaseUnavailable)?;

    let canonical_operator = expected
        .remove("consensus_operator_recovery")
        .ok_or(RecoveryError::DatabaseUnavailable)?;
    let canonical_membership_scope = expected
        .remove("consensus_membership_scope")
        .ok_or(RecoveryError::DatabaseUnavailable)?;
    let canonical_membership_history = expected
        .remove("consensus_membership_history")
        .ok_or(RecoveryError::DatabaseUnavailable)?;
    let canonical_membership_terminal_history = expected
        .remove("consensus_membership_terminal_history")
        .ok_or(RecoveryError::DatabaseUnavailable)?;
    let canonical_candidate_bootstrap = expected
        .remove("consensus_candidate_bootstrap")
        .ok_or(RecoveryError::DatabaseUnavailable)?;
    let canonical_fenced_receipts = expected
        .remove("consensus_fenced_transition_receipts")
        .ok_or(RecoveryError::DatabaseUnavailable)?;
    let canonical_fenced_activation = expected
        .remove("consensus_fenced_transition_activation")
        .ok_or(RecoveryError::DatabaseUnavailable)?;
    expected
        .remove("restore_scan_state")
        .ok_or(RecoveryError::DatabaseUnavailable)?;

    canonical
        .execute_batch("DROP TABLE consensus_operator_recovery")
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    consensus::install_recovery_validation_schema_sync(&canonical, true)
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    let add_on_operator = schema_object_sql(&canonical, "consensus_operator_recovery")?
        .ok_or(RecoveryError::DatabaseUnavailable)?;
    canonical
        .execute_batch("DROP TABLE consensus_operator_recovery")
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    consensus::install_migrated_operator_recovery_validation_schema_sync(&canonical)
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    let migrated_operator = schema_object_sql(&canonical, "consensus_operator_recovery")?
        .ok_or(RecoveryError::DatabaseUnavailable)?;

    let mut observed = recovery_schema_manifest(conn)?;
    observed
        .remove("consensus_identity")
        .ok_or(RecoveryError::CorruptReplica)?;
    if matches!(
        protected_roster_layout,
        consensus::ProtectedRosterRecoveryLayout::Prepared
            | consensus::ProtectedRosterRecoveryLayout::Activated
    ) {
        for table in PROTECTED_ROSTER_SCHEMA_TABLES {
            observed
                .remove(*table)
                .ok_or(RecoveryError::CorruptReplica)?;
        }
    }
    if v2_ledger_layout == consensus::FencedTransitionV2LedgerLayout::Activated {
        for table in [
            "consensus_fenced_transition_v2_receipts",
            "consensus_fenced_transition_v2_activation",
            "consensus_fenced_transition_v2_history",
        ] {
            observed
                .remove(table)
                .ok_or(RecoveryError::CorruptReplica)?;
        }
    }
    let observed_lease = observed
        .remove("leases")
        .ok_or(RecoveryError::CorruptReplica)?;
    match (legacy_lease_has_acquired_at(conn)?, observed_lease) {
        (true, sql) if sql == canonical_lease => {}
        (false, sql) if sql == pre_acquisition_timestamp_lease => {}
        _ => return Err(RecoveryError::CorruptReplica),
    }
    match observed.remove("restore_scan_state") {
        Some(_) if has_restore_scan_state => {}
        None if has_restore_scan_state => return Err(RecoveryError::CorruptReplica),
        None => {}
        Some(_) => return Err(RecoveryError::CorruptReplica),
    }
    match observed.remove("consensus_operator_recovery") {
        Some(sql)
            if sql == canonical_operator || sql == add_on_operator || sql == migrated_operator => {}
        Some(_) => return Err(RecoveryError::CorruptReplica),
        None if require_recovery_table => return Err(RecoveryError::CorruptReplica),
        None => {}
    }
    match observed.remove("consensus_membership_scope") {
        Some(sql) if sql == canonical_membership_scope => {}
        Some(_) => return Err(RecoveryError::CorruptReplica),
        // The fixed-membership predecessor schema is migrated transactionally
        // on the next writable consensus open.
        None => {}
    }
    match observed.remove("consensus_membership_history") {
        Some(sql) if sql == canonical_membership_history => {}
        Some(_) => return Err(RecoveryError::CorruptReplica),
        None => {}
    }
    match observed.remove("consensus_membership_terminal_history") {
        Some(sql) if sql == canonical_membership_terminal_history => {}
        Some(_) => return Err(RecoveryError::CorruptReplica),
        // Terminal outcome history is a bounded add-on installed on the next
        // writable consensus open. Read-only recovery must still inspect
        // replicas created before this feature.
        None => {}
    }
    match observed.remove("consensus_candidate_bootstrap") {
        Some(sql) if sql == canonical_candidate_bootstrap => {}
        Some(_) => return Err(RecoveryError::CorruptReplica),
        // The candidate tombstone is a new bounded add-on and is installed
        // transactionally on the next writable consensus open.
        None => {}
    }
    match observed.remove("consensus_fenced_transition_receipts") {
        Some(sql) if sql == canonical_fenced_receipts => {}
        Some(_)
            if fenced_receipt_commitment_columns(conn)?
                == FencedReceiptCommitmentColumns::Neither =>
        {
            let has_rows: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM consensus_fenced_transition_receipts LIMIT 1)",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| RecoveryError::CorruptReplica)?;
            if has_rows {
                return Err(RecoveryError::CorruptReplica);
            }
        }
        Some(_) => return Err(RecoveryError::CorruptReplica),
        // The receipt ledger is an additive tombstone table. Pre-ledger
        // replicas are inspected as an empty ledger and upgrade on reopen.
        None => {}
    }
    match observed.remove("consensus_fenced_transition_activation") {
        Some(sql) if sql == canonical_fenced_activation => {}
        Some(_) => return Err(RecoveryError::CorruptReplica),
        // This is unreachable for a correctly-classified markerless #684
        // replica because it returned above. Keep the layout branch explicit:
        // recovery inspection must never turn a read-only predecessor into a
        // V2-shaped database merely to validate its manifest.
        None if receipt_ledger_layout
            == consensus::FencedTransitionReceiptLedgerLayout::Published684 => {}
        None => return Err(RecoveryError::CorruptReplica),
    }
    if observed != expected {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FencedReceiptCommitmentColumns {
    Neither,
    Both,
    Partial,
}

fn fenced_receipt_commitment_columns(
    conn: &Connection,
) -> Result<FencedReceiptCommitmentColumns, RecoveryError> {
    let mut statement = conn
        .prepare("SELECT name FROM pragma_table_info('consensus_fenced_transition_receipts')")
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| RecoveryError::CorruptReplica)?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    Ok(
        match (
            columns.contains("binding_digest"),
            columns.contains("response_digest"),
        ) {
            (false, false) => FencedReceiptCommitmentColumns::Neither,
            (true, true) => FencedReceiptCommitmentColumns::Both,
            _ => FencedReceiptCommitmentColumns::Partial,
        },
    )
}

fn recovery_schema_manifest(conn: &Connection) -> Result<BTreeMap<String, String>, RecoveryError> {
    let mut statement = conn
        .prepare(
            "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let mut rows = statement
        .query([])
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let mut manifest = BTreeMap::new();
    while let Some(row) = rows.next().map_err(|_| RecoveryError::CorruptReplica)? {
        if manifest.len() >= consensus::CONSENSUS_SCHEMA_MAX_OBJECTS {
            return Err(RecoveryError::CorruptReplica);
        }
        let kind = row
            .get::<_, String>(0)
            .map_err(|_| RecoveryError::CorruptReplica)?;
        let name = row
            .get::<_, String>(1)
            .map_err(|_| RecoveryError::CorruptReplica)?;
        let sql = row
            .get::<_, Option<String>>(2)
            .map_err(|_| RecoveryError::CorruptReplica)?
            .ok_or(RecoveryError::CorruptReplica)?;
        if kind == "index" {
            let expected = match name.as_str() {
                "consensus_fenced_transition_receipts_due" => normalize_schema_sql(
                    "CREATE INDEX consensus_fenced_transition_receipts_due ON consensus_fenced_transition_receipts (retained_until, request_id) WHERE response_json IS NOT NULL",
                ),
                "consensus_fenced_transition_v2_receipts_reclaim" => normalize_schema_sql(
                    "CREATE INDEX consensus_fenced_transition_v2_receipts_reclaim ON consensus_fenced_transition_v2_receipts (history_epoch, ordinal)",
                ),
                "consensus_fenced_transition_v2_receipts_due" => normalize_schema_sql(
                    "CREATE INDEX consensus_fenced_transition_v2_receipts_due ON consensus_fenced_transition_v2_receipts (retained_until, request_id) WHERE response_json IS NOT NULL",
                ),
                "consensus_protected_roster_reclaim_due" => normalize_schema_sql(
                    "CREATE INDEX consensus_protected_roster_reclaim_due ON consensus_protected_roster_rows(terminalized_at,binding) WHERE state=2",
                ),
                "consensus_protected_roster_partition_epoch" => normalize_schema_sql(
                    "CREATE INDEX consensus_protected_roster_partition_epoch ON consensus_protected_roster_rows(partition,history_epoch,binding)",
                ),
                "consensus_protected_roster_terminal_sequence" => normalize_schema_sql(
                    "CREATE UNIQUE INDEX consensus_protected_roster_terminal_sequence ON consensus_protected_roster_rows(terminal_sequence) WHERE terminal_sequence IS NOT NULL",
                ),
                _ => return Err(RecoveryError::CorruptReplica),
            };
            if normalize_schema_sql(&sql) != expected {
                return Err(RecoveryError::CorruptReplica);
            }
            continue;
        }
        if kind != "table"
            || name.len() > MAX_SCHEMA_SQL_BYTES
            || sql.len() > MAX_SCHEMA_SQL_BYTES
            || manifest.insert(name, normalize_schema_sql(&sql)).is_some()
        {
            return Err(RecoveryError::CorruptReplica);
        }
    }
    Ok(manifest)
}

fn schema_object_sql(conn: &Connection, name: &str) -> Result<Option<String>, RecoveryError> {
    conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map(|sql| sql.map(|sql| normalize_schema_sql(&sql)))
    .map_err(|_| RecoveryError::CorruptReplica)
}

fn hash_legacy_state(
    conn: &Connection,
    budget: &mut InspectionBudget,
) -> Result<RecoveryDigest, RecoveryError> {
    let mut hasher = Sha256::new();
    hasher.update(LEGACY_BRANCH_DOMAIN);
    let session_records_query =
        "SELECT * FROM session_records ORDER BY tenant, nf_kind, key_type, stable_id";
    hash_query_rows_with_identity(
        conn,
        session_records_query,
        session_records_query,
        budget,
        &mut hasher,
    )?;
    hash_legacy_lease_rows(conn, budget, &mut hasher)?;
    for query in [
        "SELECT * FROM key_fences ORDER BY tenant, nf_kind, key_type, stable_id",
        "SELECT * FROM lease_globals ORDER BY key",
        "SELECT * FROM session_replication_log ORDER BY sequence",
    ] {
        hash_query_rows_with_identity(conn, query, query, budget, &mut hasher)?;
    }
    Ok(RecoveryDigest::from_bytes(hasher.finalize().into()))
}

fn hash_logical_state(
    conn: &Connection,
    budget: &mut InspectionBudget,
) -> Result<RecoveryDigest, RecoveryError> {
    let mut hasher = Sha256::new();
    hasher.update(LOGICAL_STATE_DOMAIN);
    let session_records_query =
        "SELECT * FROM session_records ORDER BY tenant, nf_kind, key_type, stable_id";
    hash_query_rows_with_identity(
        conn,
        session_records_query,
        session_records_query,
        budget,
        &mut hasher,
    )?;
    hash_legacy_lease_rows(conn, budget, &mut hasher)?;
    for query in [
        "SELECT * FROM key_fences ORDER BY tenant, nf_kind, key_type, stable_id",
        "SELECT * FROM lease_globals ORDER BY key",
    ] {
        hash_query_rows_with_identity(conn, query, query, budget, &mut hasher)?;
    }
    Ok(RecoveryDigest::from_bytes(hasher.finalize().into()))
}

/// Hash the logical data V2 must leave untouched.  The normal logical-state
/// hash includes `leases.active` and the two allocator values.  Finalization
/// deliberately writes those values, so comparing its normal digest to the
/// predecessor would reject a successful recovery.  Keep those writes out of
/// this projection and authenticate their exact postconditions separately.
fn hash_recovery_v2_invariant_state<B: RecoveryV2InvariantWorkBudget>(
    conn: &Connection,
    budget: &mut B,
) -> Result<RecoveryDigest, RecoveryError> {
    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_V2_INVARIANT_STATE_DOMAIN);
    let session_records_query =
        "SELECT * FROM session_records ORDER BY tenant, nf_kind, key_type, stable_id";
    hash_query_rows_with_identity(
        conn,
        session_records_query,
        session_records_query,
        budget,
        &mut hasher,
    )?;
    let lease_execution_query = if legacy_lease_has_acquired_at(conn)? {
        RECOVERY_V2_INVARIANT_LEASES_HASH_QUERY
    } else {
        PRE_ACQUISITION_RECOVERY_V2_INVARIANT_LEASES_HASH_QUERY
    };
    hash_query_rows_with_identity(
        conn,
        RECOVERY_V2_INVARIANT_LEASES_HASH_QUERY,
        lease_execution_query,
        budget,
        &mut hasher,
    )?;
    let key_fences_query = "SELECT * FROM key_fences ORDER BY tenant, nf_kind, key_type, stable_id";
    hash_query_rows_with_identity(
        conn,
        key_fences_query,
        key_fences_query,
        budget,
        &mut hasher,
    )?;
    let globals_query = "SELECT * FROM lease_globals WHERE key NOT IN ('next_fence', 'next_credential_id') ORDER BY key";
    hash_query_rows_with_identity(conn, globals_query, globals_query, budget, &mut hasher)?;
    Ok(RecoveryDigest::from_bytes(hasher.finalize().into()))
}

/// Recompute the exact V2 predecessor projection while the consensus apply
/// transaction is still mutation-free.  This uses the same row encoding,
/// query identities, legacy lease normalization, and stable domain as offline
/// inspection, with fixed protocol bounds because an apply command does not
/// carry caller-selected recovery limits.
pub(crate) fn recovery_v2_invariant_state_digest_for_apply(
    conn: &Connection,
) -> Result<[u8; 32], RecoveryError> {
    let mut budget = RecoveryV2InvariantProtocolBudget::new();
    Ok(hash_recovery_v2_invariant_state(conn, &mut budget)?.as_bytes())
}

fn hash_query_rows_with_identity<B: RecoveryV2InvariantWorkBudget>(
    conn: &Connection,
    identity_query: &str,
    execution_query: &str,
    budget: &mut B,
    hasher: &mut Sha256,
) -> Result<(), RecoveryError> {
    hasher.update(
        u64::try_from(identity_query.len())
            .map_err(|_| RecoveryError::WorkLimitExceeded)?
            .to_be_bytes(),
    );
    hasher.update(identity_query.as_bytes());
    hash_query_rows(conn, execution_query, budget, hasher)
}

fn hash_legacy_lease_rows(
    conn: &Connection,
    budget: &mut InspectionBudget,
    hasher: &mut Sha256,
) -> Result<(), RecoveryError> {
    let execution_query = if legacy_lease_has_acquired_at(conn)? {
        LEASES_HASH_QUERY
    } else {
        PRE_ACQUISITION_LEASES_HASH_QUERY
    };
    hash_query_rows_with_identity(conn, LEASES_HASH_QUERY, execution_query, budget, hasher)
}

// Both current replicas and the legacy checkpoints admitted by this offline
// quorum-recovery workflow are consensus inputs. The retained 1 MiB consensus
// cap is therefore intentional here; this is not standalone-store inspection.
fn validate_consensus_sealed_records(
    conn: &Connection,
    budget: &mut InspectionBudget,
) -> Result<(), RecoveryError> {
    let (count, max_value, total_value): (i64, i64, i64) = conn
        .query_row(
            r#"
            SELECT COUNT(*),
                   COALESCE(MAX(MAX(length(stable_id), length(payload))), 0),
                   COALESCE(SUM(
                       length(tenant) + length(nf_kind) + length(key_type) +
                       length(stable_id) + length(owner) + length(state_class) +
                       length(state_type) + COALESCE(length(expires_at), 0) +
                       length(payload)
                   ), 0)
            FROM session_records
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| inspection_sql_error(error, budget))?;
    let count = u64::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
    let max_value = u64::try_from(max_value).map_err(|_| RecoveryError::CorruptReplica)?;
    let total_value = u64::try_from(total_value).map_err(|_| RecoveryError::CorruptReplica)?;
    if count > budget.limits.max_rows()
        || max_value > budget.limits.max_value_bytes()
        || total_value > budget.limits.max_total_value_bytes()
    {
        return Err(RecoveryError::WorkLimitExceeded);
    }

    let mut statement = conn
        .prepare(
            r#"
            SELECT tenant, nf_kind, key_type, stable_id, generation, owner,
                   fence, state_class, state_type, expires_at, payload, encoding
            FROM session_records
            ORDER BY tenant, nf_kind, key_type, stable_id
            "#,
        )
        .map_err(|error| inspection_sql_error(error, budget))?;
    let mut rows = statement
        .query([])
        .map_err(|error| budget.map_sql_error(error))?;
    while let Some(row) = rows.next().map_err(|error| budget.map_sql_error(error))? {
        budget.consume_row()?;
        match row
            .get_ref(3)
            .map_err(|error| inspection_sql_error(error, budget))?
        {
            ValueRef::Blob(value)
                if (crate::STABLE_ID_MIN_BYTES..=crate::STABLE_ID_MAX_BYTES)
                    .contains(&value.len()) => {}
            _ => return Err(RecoveryError::CorruptReplica),
        }
        for column in [0_usize, 1, 2, 3, 5, 7, 8, 9, 10] {
            match row
                .get_ref(column)
                .map_err(|error| inspection_sql_error(error, budget))?
            {
                ValueRef::Null if column == 9 => {}
                ValueRef::Text(value) | ValueRef::Blob(value) => {
                    budget.consume_value(value.len())?
                }
                _ => return Err(RecoveryError::CorruptReplica),
            }
        }
        let record = crate::sqlite::ops::stored_record_from_row(
            row.get(0).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(1).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(2).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(3).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(4).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(5).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(6).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(7).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(8).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(9).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(10).map_err(|_| RecoveryError::CorruptReplica)?,
            row.get(11).map_err(|_| RecoveryError::CorruptReplica)?,
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
        crate::sqlite::validate_consensus_record(&record)
            .map_err(|_| RecoveryError::CorruptReplica)?;
    }
    Ok(())
}

fn validate_legacy_lease_state(
    conn: &Connection,
    budget: &mut InspectionBudget,
) -> Result<(), RecoveryError> {
    let has_acquired_at = legacy_lease_has_acquired_at(conn)?;
    let mut row_count = 0_u64;
    let mut maximum_value_bytes = 0_u64;
    let mut total_value_bytes = 0_u64;
    let leases_preflight = if has_acquired_at {
        "SELECT COUNT(*), COALESCE(MAX(MAX(length(tenant), length(nf_kind), length(key_type), length(stable_id), length(owner), COALESCE(length(acquired_at), 0), length(guard_expires_at))), 0), COALESCE(SUM(length(tenant) + length(nf_kind) + length(key_type) + length(stable_id) + length(owner) + COALESCE(length(acquired_at), 0) + length(guard_expires_at)), 0) FROM leases"
    } else {
        "SELECT COUNT(*), COALESCE(MAX(MAX(length(tenant), length(nf_kind), length(key_type), length(stable_id), length(owner), length(guard_expires_at))), 0), COALESCE(SUM(length(tenant) + length(nf_kind) + length(key_type) + length(stable_id) + length(owner) + length(guard_expires_at)), 0) FROM leases"
    };
    for query in [
        leases_preflight,
        "SELECT COUNT(*), COALESCE(MAX(MAX(length(tenant), length(nf_kind), length(key_type), length(stable_id))), 0), COALESCE(SUM(length(tenant) + length(nf_kind) + length(key_type) + length(stable_id)), 0) FROM key_fences",
        "SELECT COUNT(*), COALESCE(MAX(length(key)), 0), COALESCE(SUM(length(key)), 0) FROM lease_globals",
    ] {
        let (count, maximum, total): (i64, i64, i64) = conn
            .query_row(query, [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|error| inspection_sql_error(error, budget))?;
        row_count = row_count
            .checked_add(u64::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        maximum_value_bytes = maximum_value_bytes
            .max(u64::try_from(maximum).map_err(|_| RecoveryError::CorruptReplica)?);
        total_value_bytes = total_value_bytes
            .checked_add(u64::try_from(total).map_err(|_| RecoveryError::CorruptReplica)?)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
    }
    budget.consume_table_scan(row_count, maximum_value_bytes, total_value_bytes)?;
    if has_acquired_at {
        consensus::validate_lease_state_sync(conn).map_err(|_| {
            if budget.started.elapsed() >= budget.limits.max_duration() {
                RecoveryError::WorkLimitExceeded
            } else {
                RecoveryError::CorruptReplica
            }
        })?;
    } else {
        validate_pre_acquisition_lease_state(conn, budget)?;
    }
    budget.check()
}

/// Validate the exact pre-`acquired_at` table without mutating a query-only
/// recovery connection.  The explicit `NULL` projection is the same
/// non-authoritative marker a writable migration appends to each legacy row.
fn validate_pre_acquisition_lease_state(
    conn: &Connection,
    budget: &InspectionBudget,
) -> Result<(), RecoveryError> {
    let mut maximum_fence = 0_u64;
    let mut maximum_credential = 0_u64;
    let mut lease_statement = conn
        .prepare(
            r#"
            SELECT tenant, nf_kind, key_type, stable_id, active, credential_id,
                   owner, fence, CAST(NULL AS TEXT), expires_at_unix_ms, guard_expires_at
            FROM leases
            "#,
        )
        .map_err(|error| inspection_sql_error(error, budget))?;
    let leases = lease_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, String>(10)?,
            ))
        })
        .map_err(|error| inspection_sql_error(error, budget))?;
    for row in leases {
        let (
            tenant,
            nf_kind,
            key_type,
            stable_id,
            active,
            credential,
            owner,
            fence,
            acquired_at,
            expires_at_unix_ms,
            guard_expires_at,
        ) = row.map_err(|error| inspection_sql_error(error, budget))?;
        ops::persisted_session_key(tenant, nf_kind, key_type, stable_id)
            .map_err(|_| RecoveryError::CorruptReplica)?;
        if !matches!(active, 0 | 1) {
            return Err(RecoveryError::CorruptReplica);
        }
        let credential = consensus::checked_positive_u64(credential)
            .map_err(|_| RecoveryError::CorruptReplica)?;
        let fence =
            consensus::checked_positive_u64(fence).map_err(|_| RecoveryError::CorruptReplica)?;
        ops::persisted_owner_id(owner).map_err(|_| RecoveryError::CorruptReplica)?;
        let guard_expires_at_raw = guard_expires_at;
        let guard_expires_at = Timestamp::from_str(&guard_expires_at_raw)
            .map_err(|_| RecoveryError::CorruptReplica)?;
        if ops::format_rfc3339_normalized(guard_expires_at) != guard_expires_at_raw {
            return Err(RecoveryError::CorruptReplica);
        }
        if acquired_at.is_some_and(|acquired_at| {
            ops::persisted_normalized_timestamp(Some(acquired_at))
                .is_none_or(|acquired_at| acquired_at > guard_expires_at)
        }) {
            return Err(RecoveryError::CorruptReplica);
        }
        let guard_expires_at_unix_ms = ops::timestamp_unix_millis(guard_expires_at)
            .map_err(|_| RecoveryError::CorruptReplica)?;
        if (active == 1 && expires_at_unix_ms != guard_expires_at_unix_ms)
            || (active == 0 && expires_at_unix_ms < guard_expires_at_unix_ms)
        {
            return Err(RecoveryError::CorruptReplica);
        }
        maximum_fence = maximum_fence.max(fence);
        maximum_credential = maximum_credential.max(credential);
    }

    let mut fence_statement = conn
        .prepare("SELECT tenant, nf_kind, key_type, stable_id, fence FROM key_fences")
        .map_err(|error| inspection_sql_error(error, budget))?;
    let fences = fence_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(|error| inspection_sql_error(error, budget))?;
    for row in fences {
        let (tenant, nf_kind, key_type, stable_id, fence) =
            row.map_err(|error| inspection_sql_error(error, budget))?;
        ops::persisted_session_key(tenant, nf_kind, key_type, stable_id)
            .map_err(|_| RecoveryError::CorruptReplica)?;
        maximum_fence = maximum_fence.max(
            consensus::checked_positive_u64(fence).map_err(|_| RecoveryError::CorruptReplica)?,
        );
    }

    let stale_or_missing_fence = conn
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM session_records AS record
                LEFT JOIN key_fences AS fence
                  ON fence.tenant = record.tenant
                 AND fence.nf_kind = record.nf_kind
                 AND fence.key_type = record.key_type
                 AND fence.stable_id = record.stable_id
                WHERE fence.fence IS NULL OR fence.fence < record.fence
                UNION ALL
                SELECT 1
                FROM leases AS lease
                LEFT JOIN key_fences AS fence
                  ON fence.tenant = lease.tenant
                 AND fence.nf_kind = lease.nf_kind
                 AND fence.key_type = lease.key_type
                 AND fence.stable_id = lease.stable_id
                WHERE fence.fence IS NULL OR fence.fence != lease.fence
            )
            "#,
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|error| inspection_sql_error(error, budget))?;
    if stale_or_missing_fence {
        return Err(RecoveryError::CorruptReplica);
    }

    let mut next_fence = None;
    let mut next_credential = None;
    let mut globals_statement = conn
        .prepare("SELECT key, val FROM lease_globals ORDER BY key")
        .map_err(|error| inspection_sql_error(error, budget))?;
    let globals = globals_statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(|error| inspection_sql_error(error, budget))?;
    for row in globals {
        let (key, value) = row.map_err(|error| inspection_sql_error(error, budget))?;
        let value =
            consensus::checked_positive_u64(value).map_err(|_| RecoveryError::CorruptReplica)?;
        let slot = match key.as_str() {
            "next_fence" => &mut next_fence,
            "next_credential_id" => &mut next_credential,
            _ => return Err(RecoveryError::CorruptReplica),
        };
        if slot.replace(value).is_some() {
            return Err(RecoveryError::CorruptReplica);
        }
    }
    if next_fence.is_none_or(|next| next <= maximum_fence)
        || next_credential.is_none_or(|next| next <= maximum_credential)
    {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok(())
}

fn validate_replication_sequence_domain(
    conn: &Connection,
    budget: &mut InspectionBudget,
    invalidation_floor: u64,
) -> Result<u64, RecoveryError> {
    let (minimum, maximum, count, max_value, total_value): (
        Option<i64>,
        Option<i64>,
        i64,
        i64,
        i64,
    ) = conn
        .query_row(
            r#"
            SELECT MIN(sequence), MAX(sequence), COUNT(*),
                   COALESCE(MAX(MAX(length(tx_id), length(entry_json), length(timestamp))), 0),
                   COALESCE(SUM(length(tx_id) + length(entry_json) + length(timestamp)), 0)
            FROM session_replication_log
            "#,
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .map_err(|error| inspection_sql_error(error, budget))?;
    let count = u64::try_from(count).map_err(|_| RecoveryError::CorruptReplica)?;
    let max_value = u64::try_from(max_value).map_err(|_| RecoveryError::CorruptReplica)?;
    let total_value = u64::try_from(total_value).map_err(|_| RecoveryError::CorruptReplica)?;
    if count > budget.limits.max_rows()
        || max_value > budget.limits.max_value_bytes()
        || total_value > budget.limits.max_total_value_bytes()
    {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    if count == 0 {
        if minimum.is_some() || maximum.is_some() {
            return Err(RecoveryError::CorruptReplica);
        }
        return Ok(invalidation_floor);
    }
    let minimum = minimum
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(RecoveryError::CorruptReplica)?;
    let maximum = maximum
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(RecoveryError::CorruptReplica)?;
    let expected_minimum = invalidation_floor
        .checked_add(1)
        .ok_or(RecoveryError::CorruptReplica)?;
    let expected_maximum = invalidation_floor
        .checked_add(count)
        .ok_or(RecoveryError::CorruptReplica)?;
    if minimum != expected_minimum || maximum != expected_maximum {
        return Err(RecoveryError::CorruptReplica);
    }

    let mut statement = conn
        .prepare(
            "SELECT sequence, tx_id, entry_json, timestamp FROM session_replication_log ORDER BY sequence",
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let mut rows = statement
        .query([])
        .map_err(|error| inspection_sql_error(error, budget))?;
    let mut expected = expected_minimum;
    while let Some(row) = rows
        .next()
        .map_err(|error| inspection_sql_error(error, budget))?
    {
        budget.consume_row()?;
        let tx_id = match row
            .get_ref(1)
            .map_err(|error| inspection_sql_error(error, budget))?
        {
            ValueRef::Text(value)
                if (REPLICATION_TX_ID_MIN_BYTES..=REPLICATION_TX_ID_MAX_BYTES)
                    .contains(&value.len()) =>
            {
                budget.consume_value(value.len())?;
                let value =
                    std::str::from_utf8(value).map_err(|_| RecoveryError::CorruptReplica)?;
                ReplicationTxId::new(value).map_err(|_| RecoveryError::CorruptReplica)?
            }
            _ => return Err(RecoveryError::CorruptReplica),
        };
        for column in [2_usize, 3] {
            match row
                .get_ref(column)
                .map_err(|error| inspection_sql_error(error, budget))?
            {
                ValueRef::Text(value) => budget.consume_value(value.len())?,
                _ => return Err(RecoveryError::CorruptReplica),
            }
        }
        let stored_sequence: i64 = row.get(0).map_err(|_| RecoveryError::CorruptReplica)?;
        let encoded: String = row.get(2).map_err(|_| RecoveryError::CorruptReplica)?;
        let timestamp: String = row.get(3).map_err(|_| RecoveryError::CorruptReplica)?;
        let stored_sequence =
            u64::try_from(stored_sequence).map_err(|_| RecoveryError::CorruptReplica)?;
        let entry: ReplicationEntry =
            serde_json::from_str(&encoded).map_err(|_| RecoveryError::CorruptReplica)?;
        let entry = entry
            .into_validated()
            .map_err(|_| RecoveryError::CorruptReplica)?;
        consensus::validate_sealed_replication_op(&entry.op)
            .map_err(|_| RecoveryError::CorruptReplica)?;
        if stored_sequence != expected
            || entry.sequence != stored_sequence
            || entry.tx_id != tx_id
            || crate::sqlite::ops::format_rfc3339_normalized(entry.timestamp) != timestamp
        {
            return Err(RecoveryError::CorruptReplica);
        }
        expected = expected
            .checked_add(1)
            .ok_or(RecoveryError::CorruptReplica)?;
    }
    if expected.checked_sub(1) != Some(expected_maximum) {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok(expected_maximum)
}

fn hash_query_rows<B: RecoveryV2InvariantWorkBudget>(
    conn: &Connection,
    query: &str,
    budget: &mut B,
    hasher: &mut Sha256,
) -> Result<(), RecoveryError> {
    let mut statement = conn
        .prepare(query)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let columns = statement.column_count();
    let mut rows = statement
        .query([])
        .map_err(|error| budget.map_sql_error(error))?;
    while let Some(row) = rows.next().map_err(|error| budget.map_sql_error(error))? {
        budget.consume_row()?;
        hasher.update([0xff]);
        for column in 0..columns {
            match row
                .get_ref(column)
                .map_err(|_| RecoveryError::CorruptReplica)?
            {
                ValueRef::Null => hasher.update([0]),
                ValueRef::Integer(value) => {
                    hasher.update([1]);
                    hasher.update(value.to_be_bytes());
                }
                ValueRef::Real(_) => return Err(RecoveryError::CorruptReplica),
                ValueRef::Text(value) => {
                    feed_bounded_value(hasher, 2, value, budget)?;
                }
                ValueRef::Blob(value) => {
                    feed_bounded_value(hasher, 3, value, budget)?;
                }
            }
        }
    }
    Ok(())
}

fn feed_bounded_value<B: RecoveryV2InvariantWorkBudget>(
    hasher: &mut Sha256,
    kind: u8,
    value: &[u8],
    budget: &mut B,
) -> Result<(), RecoveryError> {
    let length = u64::try_from(value.len()).map_err(|_| RecoveryError::WorkLimitExceeded)?;
    budget.consume_value(value.len())?;
    hasher.update([kind]);
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

pub(super) fn backup_and_reset_replica(
    input: ResetInput<'_>,
) -> Result<RecoveryExecutionState, RecoveryError> {
    preflight_plan_high_waters(input.plan)?;
    let mut supplied = input
        .replicas
        .iter()
        .map(|replica| super::replica_token(input.key, &replica.replica_id))
        .collect::<Result<Vec<_>, _>>()?;
    supplied.sort_unstable();
    let planned = input
        .plan
        .body
        .evidence
        .iter()
        .map(RecoveryReplicaEvidence::replica_token)
        .collect::<Vec<_>>();
    let mut supplied_targets = input
        .targets
        .iter()
        .map(|replica| super::replica_token(input.key, &replica.replica_id))
        .collect::<Result<Vec<_>, _>>()?;
    supplied_targets.sort_unstable();
    if supplied != planned
        || supplied.windows(2).any(|pair| pair[0] == pair[1])
        || supplied_targets != input.plan.body.target_tokens
    {
        return Err(RecoveryError::StalePlan);
    }
    let workflow_dir = workflow_directory(input.backup_root, input.plan, true)?;
    let mut workflow =
        read_workflow(input.key, input.plan, &workflow_dir)?.unwrap_or(WorkflowRecord {
            version: WORKFLOW_VERSION,
            plan_digest: input.plan.plan_digest,
            limits: WorkflowLimits::from_recovery(input.limits),
            source_branch_digest: input.plan.body.source_branch_digest,
            source_authority_profile: input.plan.body.source_authority_profile,
            source_fixed_placement_policy: input.plan.body.source_fixed_placement_policy,
            source_protected_roster_digest: input.plan.body.source_protected_roster_digest,
            legacy_finalization_predecessor: None,
            terminal_proof: None,
            target_tokens: input.plan.body.target_tokens.clone(),
            state: RecoveryExecutionState::Planned,
            audit_resume_state: None,
            rejoin_proven: false,
            checkpoint_database_digest: None,
            checkpoint_database_identity: None,
            checkpoint_snapshot_digest: None,
            checkpoint_snapshot_identity: None,
            staged_database_digest: None,
            staged_database_identity: None,
            staged_snapshot_digest: None,
            staged_snapshot_identity: None,
            source_snapshot_name: None,
            staged_snapshot_name: None,
            checkpoint_progress: FileProgress::Pending,
            staged_progress: FileProgress::Pending,
            target_backups: input
                .plan
                .body
                .target_tokens
                .iter()
                .map(|token| (token.to_hex(), FileProgress::Pending))
                .collect(),
            target_installs: input
                .plan
                .body
                .target_tokens
                .iter()
                .copied()
                .map(|token| (token.to_hex(), TargetInstallState::Pending))
                .collect(),
            target_database_identities: BTreeMap::new(),
            target_temporary_database_identities: BTreeMap::new(),
            target_temporary_database_destinations: BTreeMap::new(),
            target_snapshot_identities: BTreeMap::new(),
            target_temporary_snapshot_identities: BTreeMap::new(),
            target_temporary_snapshot_destinations: BTreeMap::new(),
        });
    if workflow.limits != WorkflowLimits::from_recovery(input.limits) {
        return Err(RecoveryError::StalePlan);
    }
    validate_workflow_shape(input.plan, &workflow)?;
    // A completed execute retry is read-only: it neither creates nor alters a
    // recovery latch. Every mutating path in this explicitly drained offline
    // workflow acquires its per-file execution locks below before proceeding.
    if workflow.state == RecoveryExecutionState::Rejoined {
        return Ok(RecoveryExecutionState::Rejoined);
    }
    let execution_locks =
        acquire_fleet_execution_locks(input.key, input.plan, input.replicas, input.limits)?;
    // A completed execute retry must remain read-only with respect to the
    // fleet latch. Finalization has already cleared it on the successful path,
    // and recreating it here would regress every voter back to not-ready. If a
    // prior finalization crashed before clearing an existing latch, only a
    // finalize retry is authorized to remove it.
    ensure_fleet_latches(input.key, input.plan, input.replicas)?;
    let mut checkpoint = if workflow.checkpoint_database_digest.is_some() {
        for target in input.targets {
            verify_target_backup(input.key, input.plan, target, &workflow_dir)?;
        }
        verify_checkpoint(
            input.key,
            input.plan,
            input.source,
            &workflow_dir,
            &workflow,
            input.limits,
        )?
    } else {
        if workflow.state != RecoveryExecutionState::Planned {
            return Err(RecoveryError::BackupCorrupt);
        }
        // Re-prove the entire bound fleet, majority, and global high-waters in
        // one pass immediately before the first backup or target mutation.
        inspect_planned_fleet(&input)?;

        for target in input.targets {
            let token = super::replica_token(input.key, &target.replica_id)?.to_hex();
            let progress = workflow
                .target_backups
                .get(&token)
                .copied()
                .ok_or(RecoveryError::BackupCorrupt)?;
            if progress != FileProgress::Verified {
                if progress == FileProgress::Pending {
                    workflow
                        .target_backups
                        .insert(token.clone(), FileProgress::Copying);
                    write_workflow(input.key, &workflow_dir, &workflow)?;
                }
                ensure_target_backup(
                    input.key,
                    input.plan,
                    target,
                    &workflow_dir,
                    input.limits,
                    true,
                )?;
                #[cfg(test)]
                if input.failpoint == Some(RecoveryFailpoint::AfterTargetBackupCopy) {
                    return Err(RecoveryError::InjectedFailure);
                }
                workflow
                    .target_backups
                    .insert(token, FileProgress::Verified);
                write_workflow(input.key, &workflow_dir, &workflow)?;
            } else {
                verify_target_backup(input.key, input.plan, target, &workflow_dir)?;
            }
        }
        if workflow.checkpoint_progress == FileProgress::Pending {
            workflow.checkpoint_progress = FileProgress::Copying;
            write_workflow(input.key, &workflow_dir, &workflow)?;
        }
        let checkpoint = create_checkpoint(
            input.key,
            input.plan,
            input.source,
            &workflow_dir,
            input.limits,
            workflow.checkpoint_progress == FileProgress::Copying,
        )?;
        #[cfg(test)]
        if input.failpoint == Some(RecoveryFailpoint::AfterCheckpointCopy) {
            return Err(RecoveryError::InjectedFailure);
        }
        // Do not publish a standalone `checkpoint_progress = Verified` here.
        // The progress marker and every checkpoint commitment below form one
        // authenticated state transition.  Publishing the marker first would
        // make a process loss leave a structurally invalid workflow which a
        // resume must reject before it can re-prove the source fleet.
        #[cfg(test)]
        if input.failpoint == Some(RecoveryFailpoint::AfterCheckpointCopyBeforeVerification) {
            return Err(RecoveryError::InjectedFailure);
        }
        // A target may have changed while the sequential quarantine copies
        // were being made. Re-prove every supplied file once more after every
        // backup/checkpoint and before the first destructive installation.
        inspect_planned_fleet(&input)?;
        workflow.checkpoint_database_digest = Some(checkpoint.database_digest);
        workflow.checkpoint_database_identity = Some(checkpoint.database_identity);
        workflow.checkpoint_snapshot_digest = checkpoint.snapshot_digest;
        workflow.checkpoint_snapshot_identity = checkpoint.snapshot_identity;
        workflow.source_snapshot_name = checkpoint.snapshot_name.clone();
        workflow.checkpoint_progress = FileProgress::Verified;
        transition_record_state(&mut workflow, RecoveryExecutionState::BackupVerified)?;
        write_workflow(input.key, &workflow_dir, &workflow)?;
        checkpoint
    };

    #[cfg(test)]
    if input.failpoint == Some(RecoveryFailpoint::AfterBackup) {
        return Err(RecoveryError::InjectedFailure);
    }

    let staged = workflow_dir.join("staged.sqlite");
    let staged_snapshot = workflow_dir.join("staged-snapshot.opc");
    let (staged_snapshot_name, mut staged_database_file, staged_snapshot_pin) =
        if let Some(expected) = workflow.staged_database_digest {
            let mut file =
                PinnedSnapshotFile::open(&staged).map_err(|_| RecoveryError::BackupCorrupt)?;
            let digest = digest_pinned_file(&mut file, input.limits.max_database_bytes())?.0;
            let identity = pinned_file_identity(input.key, &file)?;
            file.verify_path_identity(&staged)?;
            if digest != expected || Some(identity) != workflow.staged_database_identity {
                return Err(RecoveryError::BackupCorrupt);
            }
            let mut snapshot_file = open_authenticated_staged_snapshot(
                input.key,
                &workflow,
                &staged_snapshot,
                workflow.staged_snapshot_name.as_deref(),
                input.limits,
            )?;
            let mut checkpoint_snapshot = if workflow.staged_snapshot_name.is_some() {
                checkpoint
                    .snapshot_file
                    .as_ref()
                    .map(PinnedSnapshotFile::try_clone)
                    .transpose()?
            } else {
                None
            };
            verify_staged_source(StagedSourceVerification {
                key: input.key,
                plan: input.plan,
                checkpoint: &checkpoint.replica,
                staged: &staged,
                database: &file,
                checkpoint_snapshot: checkpoint_snapshot.as_mut(),
                snapshot: StagedSnapshot {
                    path: &staged_snapshot,
                    file: snapshot_file.as_mut(),
                },
                source_snapshot_name: workflow.staged_snapshot_name.as_deref(),
                limits: input.limits,
            })?;
            file.verify_path_identity(&staged)?;
            (workflow.staged_snapshot_name.clone(), file, snapshot_file)
        } else {
            if workflow.staged_progress == FileProgress::Pending {
                require_path_absent(&staged)?;
                require_path_absent(&staged_snapshot)?;
                workflow.staged_progress = FileProgress::Copying;
                write_workflow(input.key, &workflow_dir, &workflow)?;
            }
            if workflow.staged_progress != FileProgress::Copying {
                return Err(RecoveryError::BackupCorrupt);
            }
            remove_regular_file_if_present(&staged)?;
            remove_regular_file_if_present(&staged_snapshot)?;
            let mut staged_source = stage_source(
                input.key,
                input.plan,
                &mut checkpoint,
                &staged,
                &staged_snapshot,
                input.limits,
            )?;
            #[cfg(test)]
            if input.failpoint == Some(RecoveryFailpoint::AfterStagedCopy) {
                return Err(RecoveryError::InjectedFailure);
            }
            let mut staged_database_file = staged_source.database_file;
            let staged_digest =
                digest_pinned_file(&mut staged_database_file, input.limits.max_database_bytes())?.0;
            let staged_identity = pinned_file_identity(input.key, &staged_database_file)?;
            staged_database_file.verify_path_identity(&staged)?;
            let (staged_snapshot_digest, staged_snapshot_identity) =
                staged_snapshot_evidence_from_pin(
                    input.key,
                    staged_source.snapshot_file.as_mut(),
                    &staged_snapshot,
                    staged_source.snapshot_name.as_deref(),
                    input.limits,
                )?;
            workflow.staged_database_digest = Some(staged_digest);
            workflow.staged_database_identity = Some(staged_identity);
            workflow.staged_snapshot_digest = staged_snapshot_digest;
            workflow.staged_snapshot_identity = staged_snapshot_identity;
            workflow.staged_snapshot_name = staged_source.snapshot_name.clone();
            workflow.staged_progress = FileProgress::Verified;
            write_workflow(input.key, &workflow_dir, &workflow)?;
            (
                staged_source.snapshot_name,
                staged_database_file,
                staged_source.snapshot_file,
            )
        };
    // The descriptor is held from authenticated staging through every target
    // database copy.  Authority is read through that descriptor, never by a
    // later lookup of `staged.sqlite`.
    let staged_fixed_immutable =
        snapshot_seal_policy_from_pinned_database(&staged_database_file, input.plan)?;
    let mut staged_snapshot_file = match staged_snapshot_pin {
        Some(file) => Some(file),
        None => open_authenticated_staged_snapshot(
            input.key,
            &workflow,
            &staged_snapshot,
            staged_snapshot_name.as_deref(),
            input.limits,
        )?,
    };

    let mut installed_snapshot_pins = Vec::with_capacity(input.targets.len());
    for target in input.targets {
        // The pin is the copied source; requiring the staged pathname to keep
        // naming it turns an otherwise byte-identical post-publication swap
        // into a recovery failure before it can be promoted anywhere.
        staged_database_file
            .verify_path_identity(&staged)
            .map_err(|_| RecoveryError::BackupCorrupt)?;
        let target_token = super::replica_token(input.key, &target.replica_id)?;
        let progress = workflow
            .target_installs
            .get(&target_token.to_hex())
            .copied()
            .ok_or(RecoveryError::BackupCorrupt)?;
        let retained_database = if progress >= TargetInstallState::DatabaseInstalled {
            let expected = workflow
                .target_database_identities
                .get(&target_token.to_hex())
                .copied()
                .ok_or(RecoveryError::BackupCorrupt)?;
            let paths = canonical_replica_paths(target, false)?;
            let database = &execution_lock_for_path(&execution_locks, &paths.database)?.database;
            // Do not reopen the public target pathname after the workflow has
            // committed this identity. The execution lock retains the exact
            // inode across retries, so a byte-identical replacement cannot
            // inherit its authority.
            if pinned_file_identity(input.key, database)? != expected {
                return Err(RecoveryError::BackupCorrupt);
            }
            #[cfg(test)]
            run_target_database_after_identity_admission_hook(&paths.database);
            Some(database)
        } else {
            revalidate_execution_lock(&execution_locks, &target.database_path)?;
            None
        };
        let mut snapshot_progress = progress;
        if snapshot_progress < TargetInstallState::SnapshotInstalled {
            if snapshot_progress == TargetInstallState::Pending {
                require_snapshot_install_temporary_absent(
                    target,
                    input.plan,
                    staged_snapshot_name.as_deref(),
                )?;
                workflow
                    .target_installs
                    .insert(target_token.to_hex(), TargetInstallState::SnapshotCopying);
                write_workflow(input.key, &workflow_dir, &workflow)?;
                snapshot_progress = TargetInstallState::SnapshotCopying;
            }
            if snapshot_progress == TargetInstallState::SnapshotCopying {
                let (snapshot_identity, installed_snapshot_pin) = match staged_snapshot_name
                    .as_deref()
                {
                    Some(file_name) => {
                        // `SnapshotCopying` has no authenticated temporary
                        // inode yet.  Any residue from a crash before the
                        // workflow write is deliberately discarded rather
                        // than inferred from bytes.
                        remove_snapshot_install_temporary_if_present(
                            target, input.plan, file_name,
                        )?;
                        let staged_file = staged_snapshot_file
                            .as_mut()
                            .ok_or(RecoveryError::BackupCorrupt)?;
                        let prepared = prepare_staged_snapshot(
                            target,
                            input.plan,
                            file_name,
                            staged_file,
                            &staged_snapshot,
                            input.limits,
                            staged_fixed_immutable,
                        )?;
                        let temporary_identity = pinned_file_identity(input.key, &prepared.file)?;
                        let promoted_path = canonical_replica_paths(target, false)?
                            .snapshots
                            .join(file_name);
                        let destination_pin = pin_promotion_destination(&promoted_path)?;
                        let destination = promotion_destination_from_pin(destination_pin.as_ref());
                        let disposition =
                            promotion_disposition(input.key, &promoted_path, destination)?;
                        workflow
                            .target_temporary_snapshot_identities
                            .insert(target_token.to_hex(), temporary_identity);
                        workflow
                            .target_temporary_snapshot_destinations
                            .insert(target_token.to_hex(), disposition);
                        workflow
                            .target_installs
                            .insert(target_token.to_hex(), TargetInstallState::SnapshotPromoting);
                        // The MAC is durable while `prepared.file` still pins
                        // the exact temporary destination.  Resume may only
                        // promote this inode, never a same-byte replacement.
                        write_workflow(input.key, &workflow_dir, &workflow)?;
                        let installed =
                            promote_prepared_snapshot(target, file_name, prepared, destination)?;
                        #[cfg(test)]
                        if input
                            .targets
                            .first()
                            .is_some_and(|first| std::ptr::eq(*first, *target))
                            && input.failpoint == Some(RecoveryFailpoint::AfterSnapshotPromotion)
                        {
                            return Err(RecoveryError::InjectedFailure);
                        }
                        let mut installed = installed;
                        verify_snapshot_matches_staged(
                            staged_file,
                            &staged_snapshot,
                            &mut installed,
                            &canonical_replica_paths(target, false)?
                                .snapshots
                                .join(file_name),
                            input.limits,
                            staged_fixed_immutable,
                        )?;
                        (
                            Some(pinned_file_identity(input.key, &installed)?),
                            Some(installed),
                        )
                    }
                    None => (None, None),
                };
                let mut next_workflow = workflow.clone();
                if let (Some(file_name), Some(installed)) = (
                    staged_snapshot_name.as_deref(),
                    installed_snapshot_pin.as_ref(),
                ) {
                    let expected_identity = workflow
                        .target_temporary_snapshot_identities
                        .get(&target_token.to_hex())
                        .copied()
                        .ok_or(RecoveryError::BackupCorrupt)?;
                    let disposition = workflow
                        .target_temporary_snapshot_destinations
                        .get(&target_token.to_hex())
                        .copied()
                        .ok_or(RecoveryError::BackupCorrupt)?;
                    let paths = canonical_replica_paths(target, false)?;
                    reconcile_completed_promotion_cleanup(
                        input.key,
                        &snapshot_promotion_temporary_path(target, input.plan, file_name)?,
                        &paths.snapshots.join(file_name),
                        &paths.snapshots,
                        expected_identity,
                        disposition,
                        installed,
                    )?;
                    next_workflow
                        .target_temporary_snapshot_identities
                        .remove(&target_token.to_hex());
                    next_workflow
                        .target_temporary_snapshot_destinations
                        .remove(&target_token.to_hex());
                }
                next_workflow
                    .target_snapshot_identities
                    .insert(target_token.to_hex(), snapshot_identity);
                next_workflow
                    .target_installs
                    .insert(target_token.to_hex(), TargetInstallState::SnapshotInstalled);
                write_workflow(input.key, &workflow_dir, &next_workflow)?;
                workflow = next_workflow;
                if let (Some(file_name), Some(installed)) = (
                    staged_snapshot_name.as_deref(),
                    installed_snapshot_pin.as_ref(),
                ) {
                    installed
                        .verify_path_identity(
                            &canonical_replica_paths(target, false)?
                                .snapshots
                                .join(file_name),
                        )
                        .map_err(|_| RecoveryError::BackupCorrupt)?;
                }
                #[cfg(test)]
                if input
                    .targets
                    .first()
                    .is_some_and(|first| std::ptr::eq(*first, *target))
                    && input.failpoint == Some(RecoveryFailpoint::AfterSnapshotInstall)
                {
                    return Err(RecoveryError::InjectedFailure);
                }
                snapshot_progress = TargetInstallState::SnapshotInstalled;
            }
            if snapshot_progress == TargetInstallState::SnapshotPromoting {
                let file_name = staged_snapshot_name
                    .as_deref()
                    .ok_or(RecoveryError::BackupCorrupt)?;
                let expected = workflow
                    .target_temporary_snapshot_identities
                    .get(&target_token.to_hex())
                    .copied()
                    .ok_or(RecoveryError::BackupCorrupt)?;
                let disposition = workflow
                    .target_temporary_snapshot_destinations
                    .get(&target_token.to_hex())
                    .copied()
                    .ok_or(RecoveryError::BackupCorrupt)?;
                let staged_file = staged_snapshot_file
                    .as_mut()
                    .ok_or(RecoveryError::BackupCorrupt)?;
                let mut installed = promote_prepared_snapshot_from_workflow(
                    input.key,
                    target,
                    input.plan,
                    file_name,
                    expected,
                    disposition,
                )?;
                verify_snapshot_matches_staged(
                    staged_file,
                    &staged_snapshot,
                    &mut installed,
                    &canonical_replica_paths(target, false)?
                        .snapshots
                        .join(file_name),
                    input.limits,
                    staged_fixed_immutable,
                )?;
                let snapshot_identity = Some(pinned_file_identity(input.key, &installed)?);
                let paths = canonical_replica_paths(target, false)?;
                reconcile_completed_promotion_cleanup(
                    input.key,
                    &snapshot_promotion_temporary_path(target, input.plan, file_name)?,
                    &paths.snapshots.join(file_name),
                    &paths.snapshots,
                    expected,
                    disposition,
                    &installed,
                )?;
                let mut next_workflow = workflow.clone();
                next_workflow
                    .target_temporary_snapshot_identities
                    .remove(&target_token.to_hex());
                next_workflow
                    .target_temporary_snapshot_destinations
                    .remove(&target_token.to_hex());
                next_workflow
                    .target_snapshot_identities
                    .insert(target_token.to_hex(), snapshot_identity);
                next_workflow
                    .target_installs
                    .insert(target_token.to_hex(), TargetInstallState::SnapshotInstalled);
                write_workflow(input.key, &workflow_dir, &next_workflow)?;
                workflow = next_workflow;
                installed
                    .verify_path_identity(
                        &canonical_replica_paths(target, false)?
                            .snapshots
                            .join(file_name),
                    )
                    .map_err(|_| RecoveryError::BackupCorrupt)?;
                #[cfg(test)]
                if input
                    .targets
                    .first()
                    .is_some_and(|first| std::ptr::eq(*first, *target))
                    && input.failpoint == Some(RecoveryFailpoint::AfterSnapshotInstall)
                {
                    return Err(RecoveryError::InjectedFailure);
                }
            }
        }
        let expected_snapshot_identity = workflow
            .target_snapshot_identities
            .get(&target_token.to_hex())
            .copied()
            .ok_or(RecoveryError::BackupCorrupt)?;
        let snapshot_path = staged_snapshot_name
            .as_deref()
            .map(|file_name| {
                validate_snapshot_name(file_name)?;
                Ok::<_, RecoveryError>(
                    canonical_replica_paths(target, false)?
                        .snapshots
                        .join(file_name),
                )
            })
            .transpose()?;
        let mut installed_snapshot_pin = match staged_snapshot_name.as_deref() {
            Some(file_name) => {
                let staged_file = staged_snapshot_file
                    .as_mut()
                    .ok_or(RecoveryError::BackupCorrupt)?;
                let installed = open_verified_installed_snapshot(
                    target,
                    file_name,
                    staged_file,
                    &staged_snapshot,
                    input.limits,
                    staged_fixed_immutable,
                )?;
                if Some(pinned_file_identity(input.key, &installed)?) != expected_snapshot_identity
                {
                    return Err(RecoveryError::BackupCorrupt);
                }
                installed
                    .verify_path_identity(
                        snapshot_path
                            .as_deref()
                            .ok_or(RecoveryError::BackupCorrupt)?,
                    )
                    .map_err(|_| RecoveryError::BackupCorrupt)?;
                Some(installed)
            }
            None if expected_snapshot_identity.is_some() => {
                return Err(RecoveryError::BackupCorrupt);
            }
            None => None,
        };
        let progress = workflow
            .target_installs
            .get(&target_token.to_hex())
            .copied()
            .ok_or(RecoveryError::BackupCorrupt)?;
        if progress < TargetInstallState::DatabaseInstalled {
            if progress == TargetInstallState::SnapshotInstalled {
                require_database_install_temporary_absent(target, input.plan)?;
                workflow
                    .target_installs
                    .insert(target_token.to_hex(), TargetInstallState::DatabaseCopying);
                write_workflow(input.key, &workflow_dir, &workflow)?;
                if let (Some(staged_file), Some(installed), Some(path)) = (
                    staged_snapshot_file.as_mut(),
                    installed_snapshot_pin.as_mut(),
                    snapshot_path.as_deref(),
                ) {
                    verify_snapshot_matches_staged(
                        staged_file,
                        &staged_snapshot,
                        installed,
                        path,
                        input.limits,
                        staged_fixed_immutable,
                    )?;
                    if Some(pinned_file_identity(input.key, installed)?)
                        != expected_snapshot_identity
                    {
                        return Err(RecoveryError::BackupCorrupt);
                    }
                }
            }
            let (installed_database_file, _prepared_database_execution_lock) =
                if let Some(expected_identity) = workflow
                    .target_temporary_database_identities
                    .get(&target_token.to_hex())
                    .copied()
                {
                    let disposition = workflow
                        .target_temporary_database_destinations
                        .get(&target_token.to_hex())
                        .copied()
                        .ok_or(RecoveryError::BackupCorrupt)?;
                    (
                        promote_prepared_database_from_workflow(
                            input.key,
                            target,
                            input.plan,
                            expected_identity,
                            disposition,
                        )?,
                        None,
                    )
                } else {
                    let prepared = prepare_staged_database(
                        target,
                        &mut staged_database_file,
                        input.plan,
                        false,
                    )?;
                    let prepared_identity = pinned_file_identity(input.key, &prepared.file)?;
                    // `RENAME_EXCHANGE` leaves the old public inode under the
                    // temporary name. Keep the existing execution lock on that
                    // old inode and acquire this second lock on the prepared
                    // inode before either becomes public. The prepared lock must
                    // survive the cleanup journal transition below.
                    let prepared_execution_lock = lock_prepared_database(&prepared.file)?;
                    let database_path = canonical_replica_paths(target, false)?.database;
                    let destination = PromotionDestination::Present(
                        &execution_lock_for_path(&execution_locks, &database_path)?.database,
                    );
                    let disposition =
                        promotion_disposition(input.key, &database_path, destination)?;
                    workflow
                        .target_temporary_database_identities
                        .insert(target_token.to_hex(), prepared_identity);
                    workflow
                        .target_temporary_database_destinations
                        .insert(target_token.to_hex(), disposition);
                    // Persist the exact temporary inode before rename.  If the
                    // process dies here, resume can only promote this pin's
                    // identity and cannot bless a replacement by content.
                    write_workflow(input.key, &workflow_dir, &workflow)?;
                    if let (Some(staged_file), Some(installed), Some(path)) = (
                        staged_snapshot_file.as_mut(),
                        installed_snapshot_pin.as_mut(),
                        snapshot_path.as_deref(),
                    ) {
                        verify_snapshot_matches_staged(
                            staged_file,
                            &staged_snapshot,
                            installed,
                            path,
                            input.limits,
                            staged_fixed_immutable,
                        )?;
                        if Some(pinned_file_identity(input.key, installed)?)
                            != expected_snapshot_identity
                        {
                            return Err(RecoveryError::BackupCorrupt);
                        }
                    }
                    #[cfg(test)]
                    if input
                        .targets
                        .first()
                        .is_some_and(|first| std::ptr::eq(*first, *target))
                        && input.failpoint
                            == Some(RecoveryFailpoint::AfterDatabaseTemporaryPrepared)
                    {
                        return Err(RecoveryError::InjectedFailure);
                    }
                    (
                        promote_prepared_database(target, prepared, destination)?,
                        Some(prepared_execution_lock),
                    )
                };
            #[cfg(test)]
            if input
                .targets
                .first()
                .is_some_and(|first| std::ptr::eq(*first, *target))
                && input.failpoint == Some(RecoveryFailpoint::AfterDatabasePromotion)
            {
                return Err(RecoveryError::InjectedFailure);
            }
            let identity = pinned_file_identity(input.key, &installed_database_file)?;
            verify_target_installed_from_pinned(
                input.key,
                input.plan,
                target,
                &installed_database_file,
                input.limits,
            )?;
            let expected_identity = workflow
                .target_temporary_database_identities
                .get(&target_token.to_hex())
                .copied()
                .ok_or(RecoveryError::BackupCorrupt)?;
            let disposition = workflow
                .target_temporary_database_destinations
                .get(&target_token.to_hex())
                .copied()
                .ok_or(RecoveryError::BackupCorrupt)?;
            let paths = canonical_replica_paths(target, false)?;
            let (parent, temporary) = database_promotion_temporary_path(target, input.plan)?;
            reconcile_completed_promotion_cleanup(
                input.key,
                &temporary,
                &paths.database,
                &parent,
                expected_identity,
                disposition,
                &installed_database_file,
            )?;
            let mut next_workflow = workflow.clone();
            next_workflow
                .target_temporary_database_identities
                .remove(&target_token.to_hex());
            next_workflow
                .target_temporary_database_destinations
                .remove(&target_token.to_hex());
            next_workflow
                .target_database_identities
                .insert(target_token.to_hex(), identity);
            next_workflow
                .target_installs
                .insert(target_token.to_hex(), TargetInstallState::DatabaseInstalled);
            write_workflow(input.key, &workflow_dir, &next_workflow)?;
            workflow = next_workflow;
            if let (Some(staged_file), Some(installed), Some(path)) = (
                staged_snapshot_file.as_mut(),
                installed_snapshot_pin.as_mut(),
                snapshot_path.as_deref(),
            ) {
                verify_snapshot_matches_staged(
                    staged_file,
                    &staged_snapshot,
                    installed,
                    path,
                    input.limits,
                    staged_fixed_immutable,
                )?;
                if Some(pinned_file_identity(input.key, installed)?) != expected_snapshot_identity {
                    return Err(RecoveryError::BackupCorrupt);
                }
            }
            installed_database_file
                .verify_path_identity(&canonical_replica_paths(target, false)?.database)
                .map_err(|_| RecoveryError::BackupCorrupt)?;
            #[cfg(test)]
            if input
                .targets
                .first()
                .is_some_and(|first| std::ptr::eq(*first, *target))
                && input.failpoint == Some(RecoveryFailpoint::AfterDatabaseInstall)
            {
                return Err(RecoveryError::InjectedFailure);
            }
        } else {
            let database = retained_database.ok_or(RecoveryError::BackupCorrupt)?;
            let finalized = matches!(
                workflow.state,
                RecoveryExecutionState::EpochCommitted | RecoveryExecutionState::Rejoined
            ) || (workflow.state == RecoveryExecutionState::AuditPending
                && workflow.audit_resume_state.is_some_and(|state| {
                    matches!(
                        state,
                        RecoveryExecutionState::EpochCommitted | RecoveryExecutionState::Rejoined
                    )
                }));
            if finalized {
                verify_target_finalized_from_pinned(
                    input.key,
                    input.plan,
                    target,
                    database,
                    input.limits,
                    workflow.legacy_finalization_predecessor.as_ref(),
                )?;
            } else if !target_matches_staged_recovery(
                input.key,
                input.plan,
                target,
                database,
                &staged_database_file,
                input.limits,
            )? {
                return Err(RecoveryError::BackupCorrupt);
            }
            // The target predicate was descriptor-bound above. Re-fence the
            // public pathname after that complete predicate before allowing
            // this retry to retain or advance workflow state.
            database
                .verify_path_identity(&canonical_replica_paths(target, false)?.database)
                .map_err(|_| RecoveryError::BackupCorrupt)?;
        }
        if let (Some(path), Some(snapshot)) = (snapshot_path, installed_snapshot_pin) {
            installed_snapshot_pins.push((path, snapshot, expected_snapshot_identity));
        }
    }
    if workflow.state != RecoveryExecutionState::BackupVerified {
        return Ok(workflow.state);
    }
    for (path, snapshot, expected_identity) in &mut installed_snapshot_pins {
        let staged_file = staged_snapshot_file
            .as_mut()
            .ok_or(RecoveryError::BackupCorrupt)?;
        verify_snapshot_matches_staged(
            staged_file,
            &staged_snapshot,
            snapshot,
            path,
            input.limits,
            staged_fixed_immutable,
        )?;
        if Some(pinned_file_identity(input.key, snapshot)?) != *expected_identity {
            return Err(RecoveryError::BackupCorrupt);
        }
    }
    transition_record_state(&mut workflow, RecoveryExecutionState::AwaitingEpochCommit)?;
    write_workflow(input.key, &workflow_dir, &workflow)?;
    for (path, snapshot, expected_identity) in &mut installed_snapshot_pins {
        let staged_file = staged_snapshot_file
            .as_mut()
            .ok_or(RecoveryError::BackupCorrupt)?;
        verify_snapshot_matches_staged(
            staged_file,
            &staged_snapshot,
            snapshot,
            path,
            input.limits,
            staged_fixed_immutable,
        )?;
        if Some(pinned_file_identity(input.key, snapshot)?) != *expected_identity {
            return Err(RecoveryError::BackupCorrupt);
        }
    }
    Ok(workflow.state)
}

fn expected_latch(plan: &RecoveryPlan, audit_pending: bool) -> consensus::OperatorRecoveryLatch {
    consensus::OperatorRecoveryLatch {
        identity: plan.body.identity,
        recovery_epoch: plan.body.next_recovery_epoch,
        plan_digest: plan.plan_digest.as_bytes(),
        audit_pending,
    }
}

fn validate_bound_replica_path(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    replica: &RecoveryReplica,
) -> Result<CanonicalReplicaPaths, RecoveryError> {
    let token = super::replica_token(key, &replica.replica_id)?;
    let planned = plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == token)
        .ok_or(RecoveryError::StalePlan)?;
    if planned.backing_identity
        != RecoveryDigest::from_bytes(replica.backing_identity.fingerprint())
    {
        return Err(RecoveryError::StalePlan);
    }
    let paths = canonical_replica_paths(replica, false)?;
    if recovery_path_binding(key, &paths)? != planned.path_binding {
        return Err(RecoveryError::StalePlan);
    }
    Ok(paths)
}

#[cfg(unix)]
fn acquire_fleet_execution_locks(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    replicas: &[RecoveryReplica],
    _limits: RecoveryLimits,
) -> Result<Vec<ReplicaExecutionLock>, RecoveryError> {
    use std::os::unix::fs::MetadataExt;

    validate_fleet_replica_set(key, plan, replicas)?;
    let mut locks = Vec::with_capacity(replicas.len());
    for replica in replicas {
        let paths = validate_bound_replica_path(key, plan, replica)?;
        let database = PinnedSnapshotFile::open(&paths.database)
            .map_err(|_| RecoveryError::FileOperationFailed)?;
        let metadata = database
            .file
            .metadata()
            .map_err(|_| RecoveryError::FileOperationFailed)?;
        let lock_file = database
            .file
            .try_clone()
            .map_err(|_| RecoveryError::FileOperationFailed)?;
        let file = nix::fcntl::Flock::lock(lock_file, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .map_err(|_| RecoveryError::FileOperationFailed)?;
        locks.push(ReplicaExecutionLock {
            path: paths.database,
            _file: file,
            device: metadata.dev(),
            inode: metadata.ino(),
            database,
        });
    }
    Ok(locks)
}

#[cfg(not(unix))]
fn acquire_fleet_execution_locks(
    _key: &RecoveryIntegrityKey,
    _plan: &RecoveryPlan,
    _replicas: &[RecoveryReplica],
    _limits: RecoveryLimits,
) -> Result<Vec<()>, RecoveryError> {
    Err(RecoveryError::InvalidRequest)
}

#[cfg(unix)]
fn revalidate_execution_lock(
    locks: &[ReplicaExecutionLock],
    path: &Path,
) -> Result<(), RecoveryError> {
    use std::os::unix::fs::MetadataExt;
    let canonical = fs::canonicalize(path).map_err(|_| RecoveryError::SourceChanged)?;
    let lock = locks
        .iter()
        .find(|lock| lock.path == canonical)
        .ok_or(RecoveryError::SourceChanged)?;
    let observed = open_regular_read(&canonical).map_err(|_| RecoveryError::SourceChanged)?;
    let metadata = observed
        .metadata()
        .map_err(|_| RecoveryError::SourceChanged)?;
    if metadata.dev() != lock.device || metadata.ino() != lock.inode {
        return Err(RecoveryError::SourceChanged);
    }
    Ok(())
}

#[cfg(not(unix))]
fn revalidate_execution_lock(_locks: &[()], _path: &Path) -> Result<(), RecoveryError> {
    Err(RecoveryError::InvalidRequest)
}

fn ensure_fleet_latches(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    replicas: &[RecoveryReplica],
) -> Result<(), RecoveryError> {
    validate_fleet_replica_set(key, plan, replicas)?;
    let expected = expected_latch(plan, false);
    for replica in replicas {
        let paths = validate_bound_replica_path(key, plan, replica)?;
        consensus::ensure_operator_recovery_latch_sync(&paths.database, expected)
            .map_err(|_| RecoveryError::FileOperationFailed)?;
    }
    Ok(())
}

pub(super) fn set_fleet_latches_audit_pending(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    replicas: &[RecoveryReplica],
    audit_pending: bool,
) -> Result<(), RecoveryError> {
    validate_fleet_replica_set(key, plan, replicas)?;
    let expected = expected_latch(plan, audit_pending);
    for replica in replicas {
        let paths = validate_bound_replica_path(key, plan, replica)?;
        consensus::set_operator_recovery_latch_audit_pending_sync(
            &paths.database,
            expected,
            audit_pending,
        )
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    }
    opc_redaction::metrics::METRICS
        .session_operator_recovery_audit_pending
        .store(
            i64::from(audit_pending),
            std::sync::atomic::Ordering::Relaxed,
        );
    Ok(())
}

/// Atomically replace finalization latches with terminal records bound to the
/// held database incarnation.  A terminal record is never an absent sidecar:
/// normal readiness treats it as inactive only after its own nofollow open
/// proves the path still names this exact finalized database.
pub(super) fn clear_fleet_latches_pinned(
    plan: &RecoveryPlan,
    pins: &FinalizationPins<'_>,
    #[cfg(test)] fail_after_terminalized_sidecars: Option<usize>,
) -> Result<(), RecoveryError> {
    let expected = expected_latch(plan, false);
    for (index, pin) in pins.latches.iter().enumerate() {
        #[cfg(not(test))]
        let _ = index;
        pin.database
            .verify_path_identity(&pin.database_path)
            .map_err(|_| RecoveryError::BackupCorrupt)?;
        let snapshot = match (
            pin.snapshot_path.as_deref(),
            pin.snapshot.as_ref(),
            pin.snapshot_digest,
        ) {
            (Some(path), Some(file), Some(_)) => Some(
                consensus::operator_recovery_terminal_snapshot(
                    path,
                    &file.file,
                    pin.fixed_immutable,
                )
                .map_err(|_| RecoveryError::FileOperationFailed)?,
            ),
            (None, None, None) => None,
            _ => return Err(RecoveryError::BackupCorrupt),
        };
        consensus::terminalize_operator_recovery_latch_sync(
            &pin.database_path,
            expected,
            &pin.database.file,
            snapshot,
        )
        .map_err(|_| RecoveryError::FileOperationFailed)?;
        pin.database
            .verify_path_identity(&pin.database_path)
            .map_err(|_| RecoveryError::BackupCorrupt)?;
        #[cfg(test)]
        if fail_after_terminalized_sidecars == Some(index.saturating_add(1)) {
            return Err(RecoveryError::InjectedFailure);
        }
    }
    opc_redaction::metrics::METRICS
        .session_operator_recovery_audit_pending
        .store(0, std::sync::atomic::Ordering::Relaxed);
    opc_redaction::metrics::METRICS
        .session_operator_recovery_required
        .store(0, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Toggle audit-pending latches under the same finalization inode pins used
/// for clearing.  This keeps the audit retry path from reintroducing a fresh
/// pathname authority between finalization checks.
pub(super) fn set_fleet_latches_audit_pending_pinned(
    plan: &RecoveryPlan,
    pins: &FinalizationPins<'_>,
    audit_pending: bool,
) -> Result<(), RecoveryError> {
    let expected = expected_latch(plan, audit_pending);
    for pin in &pins.latches {
        pin.database
            .verify_path_identity(&pin.database_path)
            .map_err(|_| RecoveryError::BackupCorrupt)?;
        consensus::set_operator_recovery_latch_audit_pending_sync(
            &pin.database_path,
            expected,
            audit_pending,
        )
        .map_err(|_| RecoveryError::FileOperationFailed)?;
        pin.database
            .verify_path_identity(&pin.database_path)
            .map_err(|_| RecoveryError::BackupCorrupt)?;
    }
    opc_redaction::metrics::METRICS
        .session_operator_recovery_audit_pending
        .store(
            i64::from(audit_pending),
            std::sync::atomic::Ordering::Relaxed,
        );
    Ok(())
}

fn validate_fleet_replica_set(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    replicas: &[RecoveryReplica],
) -> Result<(), RecoveryError> {
    let observed = replicas
        .iter()
        .map(|replica| super::replica_token(key, &replica.replica_id))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = plan
        .body
        .evidence
        .iter()
        .map(RecoveryReplicaEvidence::replica_token)
        .collect::<BTreeSet<_>>();
    if observed != expected || replicas.len() != expected.len() {
        return Err(RecoveryError::StalePlan);
    }
    Ok(())
}

fn checked_sqlite_high_water(value: u64) -> Result<i64, RecoveryError> {
    i64::try_from(value).map_err(|_| RecoveryError::WorkLimitExceeded)
}

fn preflight_successor(value: u64) -> Result<(), RecoveryError> {
    let successor = value
        .checked_add(1)
        .ok_or(RecoveryError::WorkLimitExceeded)?;
    checked_sqlite_high_water(successor).map(|_| ())
}

fn preflight_plan_high_waters(plan: &RecoveryPlan) -> Result<(), RecoveryError> {
    for value in [
        plan.body.next_recovery_epoch,
        plan.body.application_sequence_high_water,
        plan.body.watch_sequence_high_water,
        plan.body.watch_cursor_invalidation_floor,
        plan.body.fence_high_water,
        plan.body.credential_high_water,
    ] {
        preflight_successor(value)?;
    }
    Ok(())
}

fn inspect_planned_fleet(input: &ResetInput<'_>) -> Result<(), RecoveryError> {
    #[cfg(test)]
    PLANNED_FLEET_INSPECTION_COUNT.with(|count| count.set(count.get().saturating_add(1)));
    let mut observed = input
        .replicas
        .iter()
        .map(|replica| {
            inspect_replica(InspectionInput {
                key: input.key,
                replica,
                identity: input.plan.body.identity,
                expected_members: &input.plan.body.expected_members,
                limits: input.limits,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    observed.sort_by_key(RecoveryReplicaEvidence::replica_token);
    if observed == input.plan.body.evidence {
        return Ok(());
    }
    let source_token = super::replica_token(input.key, &input.source.replica_id)?;
    let observed_source = observed
        .iter()
        .find(|item| item.replica_token == source_token);
    let planned_source = input
        .plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == source_token);
    if observed_source != planned_source {
        return Err(RecoveryError::SourceChanged);
    }
    Err(RecoveryError::StalePlan)
}

#[cfg(test)]
pub(super) fn reset_planned_fleet_inspection_count() {
    PLANNED_FLEET_INSPECTION_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(super) fn planned_fleet_inspection_count() -> usize {
    PLANNED_FLEET_INSPECTION_COUNT.with(std::cell::Cell::get)
}

struct CheckpointBundle {
    replica: RecoveryReplica,
    /// The checkpoint source remains pinned until staging has copied this
    /// exact inode.  Retrying a partially completed workflow reopens and
    /// authenticates the same inode before constructing this bundle.
    database_file: PinnedSnapshotFile,
    snapshot_file: Option<PinnedSnapshotFile>,
    database_digest: RecoveryDigest,
    database_identity: RecoveryDigest,
    snapshot_digest: Option<RecoveryDigest>,
    snapshot_identity: Option<RecoveryDigest>,
    snapshot_name: Option<String>,
}

/// Stage output whose snapshot descriptor remains authoritative until the
/// workflow records its content and inode commitments.
struct StagedSourceBundle {
    database_file: PinnedSnapshotFile,
    snapshot_name: Option<String>,
    snapshot_file: Option<PinnedSnapshotFile>,
}

/// A staged snapshot pathname paired with the descriptor that authenticated
/// its inode. Keeping these together prevents verification call sites from
/// accidentally falling back to a fresh pathname open.
struct StagedSnapshot<'a> {
    path: &'a Path,
    file: Option<&'a mut PinnedSnapshotFile>,
}

struct StagedSourceVerification<'a> {
    key: &'a RecoveryIntegrityKey,
    plan: &'a RecoveryPlan,
    checkpoint: &'a RecoveryReplica,
    staged: &'a Path,
    database: &'a PinnedSnapshotFile,
    /// The checkpoint's selected snapshot, duplicated from its held
    /// descriptor before the staged copy. Semantic inspection of staged
    /// SQLite must use this descriptor at the checkpoint namespace; the
    /// staged artifact has a private workflow pathname and is verified below
    /// through `snapshot` instead.
    checkpoint_snapshot: Option<&'a mut PinnedSnapshotFile>,
    snapshot: StagedSnapshot<'a>,
    source_snapshot_name: Option<&'a str>,
    limits: RecoveryLimits,
}

fn target_backup_directory(
    workflow_dir: &Path,
    token: RecoveryDigest,
    create: bool,
) -> Result<PathBuf, RecoveryError> {
    let targets = workflow_dir.join("targets");
    if create {
        create_private_directory(&targets)?;
    }
    let directory = targets.join(token.to_hex());
    if create {
        create_private_directory(&directory)?;
    } else {
        validate_private_directory(&directory)?;
    }
    Ok(directory)
}

fn ensure_target_backup(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    target: &RecoveryReplica,
    workflow_dir: &Path,
    limits: RecoveryLimits,
    resume_partial: bool,
) -> Result<SealedBackupManifest, RecoveryError> {
    let target_token = super::replica_token(key, &target.replica_id)?;
    if !plan.body.target_tokens.contains(&target_token) {
        return Err(RecoveryError::StalePlan);
    }
    let target_path = workflow_dir.join("targets").join(target_token.to_hex());
    let target_path_preexisted = fs::symlink_metadata(&target_path).is_ok();
    let backup_dir = target_backup_directory(workflow_dir, target_token, true)?;
    if backup_dir.join("backup-manifest.json").exists() {
        return read_and_verify_backup_manifest(key, plan, target_token, &backup_dir);
    }
    if target_path_preexisted {
        if !resume_partial {
            return Err(RecoveryError::FileOperationFailed);
        }
        clean_partial_target_backup(&backup_dir)?;
    }
    if fs::read_dir(&backup_dir)
        .map_err(|_| RecoveryError::FileOperationFailed)?
        .next()
        .is_some()
    {
        return Err(RecoveryError::FileOperationFailed);
    }
    let paths = canonical_replica_paths(target, false)?;
    let target_database_file = PinnedSnapshotFile::open(&paths.database)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    let planned_target = plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == target_token)
        .ok_or(RecoveryError::StalePlan)?;
    if pinned_file_identity(key, &target_database_file)? != planned_target.file_identity {
        return Err(RecoveryError::SourceChanged);
    }
    let backup_database = backup_dir.join("target.sqlite");
    let mut backup_database_file = sqlite_backup_from_pinned(
        &target_database_file,
        &backup_database,
        limits.max_database_bytes(),
    )?;
    target_database_file
        .verify_path_identity(&paths.database)
        .map_err(|_| RecoveryError::SourceChanged)?;

    let backup_snapshots = backup_dir.join("snapshots");
    create_private_directory(&backup_snapshots)?;
    let mut files = Vec::new();
    let target_snapshot = current_snapshot_reference_from_pinned(
        &target_database_file,
        plan.body.identity,
        &paths.snapshots,
        limits,
        None,
    )?;
    let observed_snapshot_identity = target_snapshot
        .as_ref()
        .map(|snapshot| pinned_file_identity(key, &snapshot.file))
        .transpose()?;
    if observed_snapshot_identity != planned_target.current_snapshot_identity() {
        return Err(RecoveryError::SourceChanged);
    }
    let mut copied_snapshot = None;
    if let Some(mut snapshot) = target_snapshot {
        let destination = backup_snapshots.join(&snapshot.file_name);
        let mut destination_file = copy_snapshot_file_bounded(
            &mut snapshot.file,
            &destination,
            limits.max_snapshot_bytes(),
            snapshot.fixed_immutable,
        )?;
        let (digest, length) =
            digest_pinned_file(&mut destination_file, limits.max_snapshot_bytes())?;
        let identity = pinned_file_identity(key, &destination_file)?;
        destination_file.verify_path_identity(&destination)?;
        files.push(BackupFileEvidence {
            role: "snapshot".to_string(),
            byte_length: length,
            digest,
            identity,
            original_name: Some(snapshot.file_name),
        });
        copied_snapshot = Some((destination, destination_file));
    }
    // `backup_dir` does not make its nested snapshots directory durable.  The
    // nested directory entry must reach stable storage before an authenticated
    // manifest can name a copied snapshot. Keep the exact destination pin live
    // across that sync and prove the pathname still resolves to it.
    sync_target_backup_snapshot_directory(&backup_snapshots)?;
    if let Some((destination, snapshot)) = copied_snapshot.as_ref() {
        snapshot.verify_path_identity(destination)?;
    }
    let backed_up_replica = RecoveryReplica::new_bound(
        target.replica_id.clone(),
        target.backing_identity.clone(),
        target.admitted_identity,
        backup_database.clone(),
        backup_snapshots,
    );
    let backed_up_evidence = inspect_replica_from_pinned(
        InspectionInput {
            key,
            replica: &backed_up_replica,
            identity: plan.body.identity,
            expected_members: &plan.body.expected_members,
            limits,
        },
        canonical_replica_paths(&backed_up_replica, false)?,
        &backup_database_file,
        copied_snapshot.as_mut().map(|(_, file)| file),
    )?;
    if !same_checkpoint(&backed_up_evidence, planned_target) {
        return Err(RecoveryError::StalePlan);
    }
    backup_database_file.verify_path_identity(&backup_database)?;
    let (database_digest, database_length) =
        digest_pinned_file(&mut backup_database_file, limits.max_database_bytes())?;
    let database_identity = pinned_file_identity(key, &backup_database_file)?;
    backup_database_file.verify_path_identity(&backup_database)?;
    files.insert(
        0,
        BackupFileEvidence {
            role: "database".to_string(),
            byte_length: database_length,
            digest: database_digest,
            identity: database_identity,
            original_name: None,
        },
    );
    let body = BackupManifestBody {
        version: WORKFLOW_VERSION,
        plan_digest: plan.plan_digest,
        target_token,
        files,
    };
    let encoded = serde_json::to_vec(&body).map_err(|_| RecoveryError::FileOperationFailed)?;
    let mac = RecoveryDigest::from_bytes(plan_mac(key, BACKUP_MAC_DOMAIN, &[&encoded])?);
    let manifest = SealedBackupManifest { body, mac };
    atomic_write_json(&backup_dir.join("backup-manifest.json"), &manifest)?;
    let verified = read_and_verify_backup_manifest(key, plan, target_token, &backup_dir)?;
    sync_directory(&backup_dir)?;
    Ok(verified)
}

fn verify_target_backup(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    target: &RecoveryReplica,
    workflow_dir: &Path,
) -> Result<(), RecoveryError> {
    let target_token = super::replica_token(key, &target.replica_id)?;
    let directory = target_backup_directory(workflow_dir, target_token, false)?;
    read_and_verify_backup_manifest(key, plan, target_token, &directory).map(|_| ())
}

fn clean_partial_target_backup(directory: &Path) -> Result<(), RecoveryError> {
    let mut inspected = 0;
    remove_private_tree(directory, 0, &mut inspected)?;
    create_private_directory(directory)
}

fn clean_partial_checkpoint(directory: &Path) -> Result<(), RecoveryError> {
    let mut inspected = 0;
    remove_private_tree(directory, 0, &mut inspected)?;
    Ok(())
}

fn remove_private_tree(
    path: &Path,
    depth: usize,
    inspected: &mut usize,
) -> Result<(), RecoveryError> {
    if depth > 3 || *inspected > 32 {
        return Err(RecoveryError::FileOperationFailed);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| RecoveryError::FileOperationFailed)?;
    if metadata.file_type().is_symlink() {
        return Err(RecoveryError::FileOperationFailed);
    }
    if metadata.is_file() {
        validate_private_file(path).map_err(|_| RecoveryError::FileOperationFailed)?;
        return fs::remove_file(path).map_err(|_| RecoveryError::FileOperationFailed);
    }
    validate_private_directory(path)?;
    for entry in fs::read_dir(path).map_err(|_| RecoveryError::FileOperationFailed)? {
        let entry = entry.map_err(|_| RecoveryError::FileOperationFailed)?;
        *inspected = inspected
            .checked_add(1)
            .ok_or(RecoveryError::FileOperationFailed)?;
        remove_private_tree(&entry.path(), depth + 1, inspected)?;
    }
    fs::remove_dir(path).map_err(|_| RecoveryError::FileOperationFailed)
}

fn read_and_verify_backup_manifest(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    target_token: RecoveryDigest,
    backup_dir: &Path,
) -> Result<SealedBackupManifest, RecoveryError> {
    let manifest: SealedBackupManifest =
        read_bounded_json(&backup_dir.join("backup-manifest.json"), 64 * 1024)?;
    if manifest.body.version != WORKFLOW_VERSION
        || manifest.body.plan_digest != plan.plan_digest
        || manifest.body.target_token != target_token
        || !plan.body.target_tokens.contains(&target_token)
        || manifest.body.files.is_empty()
        || manifest.body.files.len() > 2
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    let encoded = serde_json::to_vec(&manifest.body).map_err(|_| RecoveryError::BackupCorrupt)?;
    verify_mac(key, BACKUP_MAC_DOMAIN, &[&encoded], manifest.mac)?;
    if manifest
        .body
        .files
        .iter()
        .filter(|file| file.role == "database" && file.original_name.is_none())
        .count()
        != 1
        || manifest
            .body
            .files
            .iter()
            .filter(|file| file.role == "snapshot" && file.original_name.is_some())
            .count()
            > 1
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    for evidence in &manifest.body.files {
        let path = match evidence.role.as_str() {
            "database" => backup_dir.join("target.sqlite"),
            "snapshot" => {
                let name = evidence
                    .original_name
                    .as_deref()
                    .ok_or(RecoveryError::BackupCorrupt)?;
                validate_snapshot_name(name).map_err(|_| RecoveryError::BackupCorrupt)?;
                backup_dir.join("snapshots").join(name)
            }
            _ => return Err(RecoveryError::BackupCorrupt),
        };
        let mut file = PinnedSnapshotFile::open(&path).map_err(|_| RecoveryError::BackupCorrupt)?;
        let (digest, length) = digest_pinned_file(&mut file, evidence.byte_length)
            .map_err(|_| RecoveryError::BackupCorrupt)?;
        let identity =
            pinned_file_identity(key, &file).map_err(|_| RecoveryError::BackupCorrupt)?;
        file.verify_path_identity(&path)
            .map_err(|_| RecoveryError::BackupCorrupt)?;
        if digest != evidence.digest
            || length != evidence.byte_length
            || identity != evidence.identity
        {
            return Err(RecoveryError::BackupCorrupt);
        }
    }
    Ok(manifest)
}

fn create_checkpoint(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    source: &RecoveryReplica,
    workflow_dir: &Path,
    limits: RecoveryLimits,
    resume_partial: bool,
) -> Result<CheckpointBundle, RecoveryError> {
    let checkpoint_dir = workflow_dir.join("checkpoint");
    if fs::symlink_metadata(&checkpoint_dir).is_ok() {
        if !resume_partial {
            return Err(RecoveryError::FileOperationFailed);
        }
        clean_partial_checkpoint(&checkpoint_dir)?;
    }
    create_private_directory(&checkpoint_dir)?;
    if fs::read_dir(&checkpoint_dir)
        .map_err(|_| RecoveryError::FileOperationFailed)?
        .next()
        .is_some()
    {
        return Err(RecoveryError::FileOperationFailed);
    }
    let source_paths = canonical_replica_paths(source, false)?;
    let source_database_file = PinnedSnapshotFile::open(&source_paths.database)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    let planned_source = plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == plan.body.source_token)
        .ok_or(RecoveryError::StalePlan)?;
    if pinned_file_identity(key, &source_database_file)? != planned_source.file_identity {
        return Err(RecoveryError::SourceChanged);
    }
    let database = checkpoint_dir.join("source.sqlite");
    let snapshots = checkpoint_dir.join("snapshots");
    create_private_directory(&snapshots)?;
    let mut database_file = sqlite_backup_from_pinned(
        &source_database_file,
        &database,
        limits.max_database_bytes(),
    )?;
    source_database_file
        .verify_path_identity(&source_paths.database)
        .map_err(|_| RecoveryError::SourceChanged)?;
    let snapshot = current_snapshot_reference_from_pinned(
        &source_database_file,
        plan.body.identity,
        &source_paths.snapshots,
        limits,
        None,
    )?;
    let (snapshot_name, snapshot_digest, snapshot_identity, mut snapshot_file) =
        if let Some(mut snapshot) = snapshot {
            if Some(pinned_file_identity(key, &snapshot.file)?)
                != planned_source.current_snapshot_identity
            {
                return Err(RecoveryError::SourceChanged);
            }
            let destination = snapshots.join(&snapshot.file_name);
            let mut destination_file = copy_snapshot_file_bounded(
                &mut snapshot.file,
                &destination,
                limits.max_snapshot_bytes(),
                snapshot.fixed_immutable,
            )?;
            let digest = digest_pinned_file(&mut destination_file, limits.max_snapshot_bytes())?.0;
            let identity = pinned_file_identity(key, &destination_file)?;
            destination_file.verify_path_identity(&destination)?;
            (
                Some(snapshot.file_name),
                Some(digest),
                Some(identity),
                Some(destination_file),
            )
        } else {
            if planned_source.current_snapshot_identity.is_some() {
                return Err(RecoveryError::SourceChanged);
            }
            (None, None, None, None)
        };
    let replica = RecoveryReplica::new_bound(
        source.replica_id.clone(),
        source.backing_identity.clone(),
        source.admitted_identity,
        &database,
        &snapshots,
    );
    let evidence = inspect_replica_from_pinned(
        InspectionInput {
            key,
            replica: &replica,
            identity: plan.body.identity,
            expected_members: &plan.body.expected_members,
            limits,
        },
        canonical_replica_paths(&replica, false)?,
        &database_file,
        snapshot_file.as_mut(),
    )?;
    let planned = plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == plan.body.source_token)
        .ok_or(RecoveryError::StalePlan)?;
    if !same_checkpoint(&evidence, planned) {
        return Err(RecoveryError::SourceChanged);
    }
    database_file.verify_path_identity(&database)?;
    let database_digest = digest_pinned_file(&mut database_file, limits.max_database_bytes())?.0;
    let database_identity = pinned_file_identity(key, &database_file)?;
    database_file.verify_path_identity(&database)?;
    sync_directory(&snapshots)?;
    sync_directory(&checkpoint_dir)?;
    Ok(CheckpointBundle {
        replica,
        database_file,
        snapshot_file,
        database_digest,
        database_identity,
        snapshot_digest,
        snapshot_identity,
        snapshot_name,
    })
}

fn verify_checkpoint(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    source: &RecoveryReplica,
    workflow_dir: &Path,
    workflow: &WorkflowRecord,
    limits: RecoveryLimits,
) -> Result<CheckpointBundle, RecoveryError> {
    let checkpoint_dir = workflow_dir.join("checkpoint");
    validate_private_directory(&checkpoint_dir)?;
    let database = checkpoint_dir.join("source.sqlite");
    let snapshots = checkpoint_dir.join("snapshots");
    validate_private_directory(&snapshots)?;
    let mut database_file =
        PinnedSnapshotFile::open(&database).map_err(|_| RecoveryError::BackupCorrupt)?;
    let database_digest = digest_pinned_file(&mut database_file, limits.max_database_bytes())?.0;
    let database_identity = pinned_file_identity(key, &database_file)?;
    database_file.verify_path_identity(&database)?;
    if Some(database_digest) != workflow.checkpoint_database_digest
        || Some(database_identity) != workflow.checkpoint_database_identity
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    let mut snapshot_file = match (
        workflow.source_snapshot_name.as_deref(),
        workflow.checkpoint_snapshot_digest,
    ) {
        (Some(name), Some(expected)) => {
            validate_snapshot_name(name)?;
            let path = snapshots.join(name);
            let mut file =
                PinnedSnapshotFile::open(&path).map_err(|_| RecoveryError::BackupCorrupt)?;
            let digest = digest_pinned_file(&mut file, limits.max_snapshot_bytes())?.0;
            let identity = pinned_file_identity(key, &file)?;
            file.verify_path_identity(&path)?;
            if digest != expected || Some(identity) != workflow.checkpoint_snapshot_identity {
                return Err(RecoveryError::BackupCorrupt);
            }
            Some(file)
        }
        (None, None) => None,
        _ => return Err(RecoveryError::BackupCorrupt),
    };
    let replica = RecoveryReplica::new_bound(
        source.replica_id.clone(),
        source.backing_identity.clone(),
        source.admitted_identity,
        &database,
        &snapshots,
    );
    let evidence = inspect_replica_from_pinned(
        InspectionInput {
            key,
            replica: &replica,
            identity: plan.body.identity,
            expected_members: &plan.body.expected_members,
            limits,
        },
        canonical_replica_paths(&replica, false)?,
        &database_file,
        snapshot_file.as_mut(),
    )?;
    let planned = plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == plan.body.source_token)
        .ok_or(RecoveryError::StalePlan)?;
    if !same_checkpoint(&evidence, planned) {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(CheckpointBundle {
        replica,
        database_file,
        snapshot_file,
        database_digest,
        database_identity,
        snapshot_digest: workflow.checkpoint_snapshot_digest,
        snapshot_identity: workflow.checkpoint_snapshot_identity,
        snapshot_name: workflow.source_snapshot_name.clone(),
    })
}

/// Whether the selected snapshot is authenticated branch authority.  This
/// mirrors `committed_branch_digest`: both a missing committed-row fallback
/// and a no-purge snapshot boundary must be retained in staging, while a
/// historical selected snapshot beside a complete physical suffix must not
/// be copied fleet-wide.
fn staged_snapshot_is_branch_authority(conn: &Connection) -> Result<bool, RecoveryError> {
    let identity =
        consensus::read_storage_identity_sync(conn).map_err(|_| RecoveryError::CorruptReplica)?;
    let committed = consensus::read_committed_sync(conn, identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let purged =
        consensus::read_purged_sync(conn, identity).map_err(|_| RecoveryError::CorruptReplica)?;
    let snapshot = consensus::read_current_snapshot_sync(conn, identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let role = current_snapshot_branch_role(
        conn,
        identity,
        committed.as_ref(),
        purged.as_ref(),
        snapshot
            .as_ref()
            .and_then(|(meta, _, _, _)| meta.last_log_id.as_ref()),
    )?;
    Ok(matches!(
        role,
        CurrentSnapshotBranchRole::Boundary | CurrentSnapshotBranchRole::CommittedFallback
    ))
}

fn stage_source(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    source: &mut CheckpointBundle,
    staged: &Path,
    staged_snapshot: &Path,
    limits: RecoveryLimits,
) -> Result<StagedSourceBundle, RecoveryError> {
    let paths = canonical_replica_paths(&source.replica, false)?;
    let staged_database_file = match plan.body.basis {
        RecoveryDecisionBasis::VerifiedCommittedMajority => {
            sqlite_backup_from_pinned(&source.database_file, staged, limits.max_database_bytes())?
        }
        RecoveryDecisionBasis::ExplicitLegacyCheckpoint => {
            convert_legacy_checkpoint_from_pinned(&source.database_file, staged, limits)?
        }
    };
    source
        .database_file
        .verify_path_identity(&paths.database)
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    let staged_replica = RecoveryReplica::new_bound(
        source.replica.replica_id.clone(),
        source.replica.backing_identity.clone(),
        source.replica.admitted_identity,
        staged.to_path_buf(),
        paths.snapshots.clone(),
    );
    let staged_evidence = inspect_replica_from_pinned(
        InspectionInput {
            key,
            replica: &staged_replica,
            identity: plan.body.identity,
            expected_members: &plan.body.expected_members,
            limits,
        },
        canonical_replica_paths(&staged_replica, false)?,
        &staged_database_file,
        source.snapshot_file.as_mut(),
    )?;
    let planned_source = plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == plan.body.source_token)
        .ok_or(RecoveryError::StalePlan)?;
    if !same_checkpoint(&staged_evidence, planned_source) {
        return Err(RecoveryError::SourceChanged);
    }
    let mut conn = open_read_write_pinned(&staged_database_file)?;
    ensure_restore_scan_metadata(&conn)?;
    // The selected snapshot is carried only when `committed_branch_digest`
    // made it branch evidence: either it supplies the missing committed
    // record or it is the exact no-purge predecessor of the retained suffix.
    // A source-local historical selection beside a complete physical suffix
    // stays digest-neutral and must not become a fleet-wide artifact.
    let carry_branch_snapshot = match plan.body.basis {
        RecoveryDecisionBasis::VerifiedCommittedMajority => {
            staged_snapshot_is_branch_authority(&conn)?
        }
        // Legacy conversion has no authenticated current-format branch
        // snapshot.  Its conversion path starts from the explicit checkpoint
        // database and must not invent a separately carried file.
        RecoveryDecisionBasis::ExplicitLegacyCheckpoint => false,
    };
    match plan.body.basis {
        RecoveryDecisionBasis::VerifiedCommittedMajority => {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| RecoveryError::FileOperationFailed)?;
            let storage_identity = consensus::read_storage_identity_sync(&tx)
                .map_err(|_| RecoveryError::CorruptReplica)?;
            consensus::activate_fenced_transition_receipt_ledger_sync(&tx, storage_identity)
                .map_err(|_| RecoveryError::CorruptReplica)?;
            let committed: Option<i64> = tx
                .query_row(
                    "SELECT log_index FROM consensus_committed WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| RecoveryError::CorruptReplica)?;
            match committed {
                Some(committed) => {
                    tx.execute(
                        "DELETE FROM consensus_log WHERE log_index > ?1",
                        [committed],
                    )
                    .map_err(|_| RecoveryError::FileOperationFailed)?;
                }
                None => {
                    tx.execute("DELETE FROM consensus_log", [])
                        .map_err(|_| RecoveryError::FileOperationFailed)?;
                }
            }
            tx.execute("DELETE FROM consensus_vote", [])
                .map_err(|_| RecoveryError::FileOperationFailed)?;
            if !carry_branch_snapshot {
                tx.execute("DELETE FROM consensus_snapshot", [])
                    .map_err(|_| RecoveryError::FileOperationFailed)?;
            }
            consensus::mark_operator_recovery_pending_sync(
                &tx,
                storage_identity,
                plan.body.next_recovery_epoch,
                plan.plan_digest.as_bytes(),
            )
            .map_err(|_| RecoveryError::CorruptReplica)?;
            tx.execute("DELETE FROM session_replication_log", [])
                .map_err(|_| RecoveryError::FileOperationFailed)?;
            tx.execute(
                "UPDATE consensus_machine SET application_sequence = ?1, watch_sequence = ?2 WHERE singleton = 1",
                rusqlite::params![
                    checked_sqlite_high_water(plan.body.application_sequence_high_water)?,
                    checked_sqlite_high_water(plan.body.watch_cursor_invalidation_floor)?,
                ],
            )
            .map_err(|_| RecoveryError::FileOperationFailed)?;
            tx.execute(
                "UPDATE consensus_operator_recovery SET watch_cursor_invalidation_floor = ?1 WHERE singleton = 1",
                [checked_sqlite_high_water(
                    plan.body.watch_cursor_invalidation_floor,
                )?],
            )
            .map_err(|_| RecoveryError::FileOperationFailed)?;
            tx.commit()
                .map_err(|_| RecoveryError::FileOperationFailed)?;
        }
        RecoveryDecisionBasis::ExplicitLegacyCheckpoint => {
            consensus::claim_legacy_checkpoint_sync(
                &conn,
                plan.body.identity,
                &plan.body.expected_members,
                plan.body.source_branch_digest.as_bytes(),
                plan.body.next_recovery_epoch,
                plan.plan_digest.as_bytes(),
                plan.body.application_sequence_high_water,
                plan.body.watch_cursor_invalidation_floor,
            )
            .map_err(|_| RecoveryError::CorruptReplica)?;
            validate_exact_recovery_schema(&conn, true)?;
        }
    }
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode = DELETE;")
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    drop(conn);
    staged_database_file
        .file
        .sync_all()
        .map_err(|_| RecoveryError::FileOperationFailed)?;

    // This is the one authoritative staged database object.  Its exact
    // descriptor selects the immutable-copy policy for the staged snapshot;
    // a later resolution of `staged.sqlite` must not make that decision.
    let staged_fixed_immutable =
        snapshot_seal_policy_from_pinned_database(&staged_database_file, plan)?;

    // Drop the checkpoint snapshot pin together with the staged metadata.
    // Passing it to `current_snapshot_reference_from_pinned` after deleting
    // the row would itself be an authority error: a descriptor with no
    // selected database reference must never become a carried snapshot.
    let checkpoint_snapshot = if carry_branch_snapshot {
        source.snapshot_file.take()
    } else {
        None
    };
    let snapshot = current_snapshot_reference_from_pinned(
        &staged_database_file,
        plan.body.identity,
        &paths.snapshots,
        limits,
        checkpoint_snapshot,
    )?;
    let (source_snapshot_name, mut staged_snapshot_file, mut checkpoint_snapshot_file) =
        if let Some(mut snapshot) = snapshot {
            snapshot.fixed_immutable = staged_fixed_immutable;
            let destination = copy_snapshot_file_bounded(
                &mut snapshot.file,
                staged_snapshot,
                limits.max_snapshot_bytes(),
                snapshot.fixed_immutable,
            )?;
            let inspection_pin = snapshot.file.try_clone()?;
            (
                Some(snapshot.file_name),
                Some(destination),
                Some(inspection_pin),
            )
        } else {
            (None, None, None)
        };
    verify_staged_source(StagedSourceVerification {
        key,
        plan,
        checkpoint: &source.replica,
        staged,
        database: &staged_database_file,
        checkpoint_snapshot: checkpoint_snapshot_file.as_mut(),
        snapshot: StagedSnapshot {
            path: staged_snapshot,
            file: staged_snapshot_file.as_mut(),
        },
        source_snapshot_name: source_snapshot_name.as_deref(),
        limits,
    })?;
    staged_database_file.verify_path_identity(staged)?;
    Ok(StagedSourceBundle {
        database_file: staged_database_file,
        snapshot_name: source_snapshot_name,
        snapshot_file: staged_snapshot_file,
    })
}

fn convert_legacy_checkpoint_from_pinned(
    source: &PinnedSnapshotFile,
    destination: &Path,
    limits: RecoveryLimits,
) -> Result<PinnedSnapshotFile, RecoveryError> {
    let source_conn = open_read_only_pinned(source)?;
    let mut source_budget = InspectionBudget::new(limits);
    validate_database_snapshot(&source_conn, &source_budget)?;
    validate_legacy_schema(&source_conn)?;
    validate_consensus_sealed_records(&source_conn, &mut source_budget)?;
    validate_legacy_lease_state(&source_conn, &mut source_budget)?;
    validate_replication_sequence_domain(&source_conn, &mut source_budget, 0)?;
    let before = hash_legacy_state(&source_conn, &mut source_budget)?;
    let source_has_acquired_at = legacy_lease_has_acquired_at(&source_conn)?;

    let destination_creator = private_create_new(destination)?;
    let destination_file =
        PinnedSnapshotFile::open(destination).map_err(|_| RecoveryError::FileOperationFailed)?;
    destination_file
        .verify_writer_identity(&destination_creator)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    destination_file
        .verify_path_identity(destination)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    let canonical = crate::sqlite::SqliteSessionBackend::canonical_schema_connection()
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    let mut schema_destination = open_read_write_created(&destination_creator)?;
    {
        let backup = Backup::new(&canonical, &mut schema_destination)
            .map_err(|_| RecoveryError::FileOperationFailed)?;
        backup
            .run_to_completion(128, Duration::ZERO, None)
            .map_err(|_| RecoveryError::FileOperationFailed)?;
    }
    drop(schema_destination);
    destination_file
        .verify_writer_identity(&destination_creator)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    destination_file
        .verify_path_identity(destination)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    let mut destination_conn = open_read_write_pinned(&destination_file)?;
    let tx = destination_conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    for table in [
        "session_records",
        "leases",
        "key_fences",
        "lease_globals",
        "session_replication_log",
    ] {
        tx.execute(&format!("DELETE FROM {table}"), [])
            .map_err(|_| RecoveryError::FileOperationFailed)?;
    }
    for (table, columns, column_count) in [
        (
            "session_records",
            "tenant, nf_kind, key_type, stable_id, generation, owner, fence, state_class, state_type, expires_at, payload, encoding",
            12,
        ),
        (
            "key_fences",
            "tenant, nf_kind, key_type, stable_id, fence",
            5,
        ),
        ("lease_globals", "key, val", 2),
        (
            "session_replication_log",
            "sequence, tx_id, entry_json, timestamp",
            4,
        ),
    ] {
        copy_exact_table(&source_conn, &tx, table, columns, column_count)?;
    }
    copy_legacy_leases(&source_conn, &tx, source_has_acquired_at)?;
    tx.commit()
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    destination_conn
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode = DELETE;")
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    drop(destination_conn);

    let destination_conn = open_read_only_pinned(&destination_file)?;
    validate_legacy_schema(&destination_conn)?;
    let mut destination_budget = InspectionBudget::new(limits);
    validate_consensus_sealed_records(&destination_conn, &mut destination_budget)?;
    validate_legacy_lease_state(&destination_conn, &mut destination_budget)?;
    validate_replication_sequence_domain(&destination_conn, &mut destination_budget, 0)?;
    let after = hash_legacy_state(&destination_conn, &mut destination_budget)?;
    if before != after {
        return Err(RecoveryError::SourceChanged);
    }
    drop(destination_conn);
    destination_file
        .verify_writer_identity(&destination_creator)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    destination_file
        .verify_path_identity(destination)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    destination_file
        .file
        .sync_all()
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    let metadata = destination_file
        .file
        .metadata()
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    if metadata.len() == 0 || metadata.len() > limits.max_database_bytes() {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    Ok(destination_file)
}

#[cfg(test)]
fn convert_legacy_checkpoint(
    source: &Path,
    destination: &Path,
    limits: RecoveryLimits,
) -> Result<(), RecoveryError> {
    let source = PinnedSnapshotFile::open(source)?;
    convert_legacy_checkpoint_from_pinned(&source, destination, limits).map(|_| ())
}

fn copy_exact_table(
    source: &Connection,
    destination: &rusqlite::Transaction<'_>,
    table: &str,
    columns: &str,
    column_count: usize,
) -> Result<(), RecoveryError> {
    copy_projected_table(source, destination, table, columns, columns, column_count)
}

fn copy_legacy_leases(
    source: &Connection,
    destination: &rusqlite::Transaction<'_>,
    source_has_acquired_at: bool,
) -> Result<(), RecoveryError> {
    let destination_columns = "tenant, nf_kind, key_type, stable_id, active, credential_id, owner, fence, acquired_at, expires_at_unix_ms, guard_expires_at";
    let source_columns = if source_has_acquired_at {
        destination_columns
    } else {
        "tenant, nf_kind, key_type, stable_id, active, credential_id, owner, fence, CAST(NULL AS TEXT) AS acquired_at, expires_at_unix_ms, guard_expires_at"
    };
    copy_projected_table(
        source,
        destination,
        "leases",
        source_columns,
        destination_columns,
        11,
    )
}

fn copy_projected_table(
    source: &Connection,
    destination: &rusqlite::Transaction<'_>,
    table: &str,
    source_columns: &str,
    destination_columns: &str,
    column_count: usize,
) -> Result<(), RecoveryError> {
    let mut statement = source
        .prepare(&format!("SELECT {source_columns} FROM {table}"))
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let mut rows = statement
        .query([])
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let placeholders = (1..=column_count)
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let insert = format!("INSERT INTO {table} ({destination_columns}) VALUES ({placeholders})");
    while let Some(row) = rows.next().map_err(|_| RecoveryError::CorruptReplica)? {
        let values = (0..column_count)
            .map(|column| row.get::<_, Value>(column))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RecoveryError::CorruptReplica)?;
        destination
            .execute(&insert, rusqlite::params_from_iter(values.iter()))
            .map_err(|_| RecoveryError::CorruptReplica)?;
    }
    Ok(())
}

fn verify_staged_source(mut input: StagedSourceVerification<'_>) -> Result<(), RecoveryError> {
    let checkpoint_paths = canonical_replica_paths(input.checkpoint, false)?;
    let staged_replica = RecoveryReplica::new_bound(
        input.checkpoint.replica_id.clone(),
        input.checkpoint.backing_identity.clone(),
        input.checkpoint.admitted_identity,
        input.staged.to_path_buf(),
        checkpoint_paths.snapshots,
    );
    let planned_source = input
        .plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == input.plan.body.source_token)
        .ok_or(RecoveryError::StalePlan)?;
    let expected_snapshot = inspect_replica_from_pinned_with(
        InspectionInput {
            key: input.key,
            replica: &staged_replica,
            identity: input.plan.body.identity,
            expected_members: &input.plan.body.expected_members,
            limits: input.limits,
        },
        canonical_replica_paths(&staged_replica, false)?,
        input.database,
        input.checkpoint_snapshot.as_deref_mut(),
        |evidence, conn| {
            if evidence.pending_recovery_epoch != Some(input.plan.body.next_recovery_epoch)
                || evidence.pending_plan_digest != Some(input.plan.plan_digest)
                || evidence.application_sequence != input.plan.body.application_sequence_high_water
                || evidence.watch_sequence != input.plan.body.watch_cursor_invalidation_floor
                || evidence.watch_cursor_invalidation_floor
                    != input.plan.body.watch_cursor_invalidation_floor
                || evidence.fence_high_water > input.plan.body.fence_high_water
                || evidence.credential_high_water > input.plan.body.credential_high_water
                || evidence.logical_state_digest != planned_source.logical_state_digest
                || evidence.authority_profile != input.plan.body.source_authority_profile
                || evidence.fixed_placement_policy != input.plan.body.source_fixed_placement_policy
                || evidence.protected_roster_digest
                    != input.plan.body.source_protected_roster_digest
            {
                return Err(RecoveryError::BackupCorrupt);
            }
            match input.source_snapshot_name {
                Some(name) => {
                    validate_snapshot_name(name)?;
                    let storage_identity = consensus::read_storage_identity_sync(conn)
                        .map_err(|_| RecoveryError::BackupCorrupt)?;
                    let scope = consensus::read_membership_scope_sync(conn, storage_identity)
                        .map_err(|_| RecoveryError::BackupCorrupt)?;
                    if scope.current_identity != input.plan.body.identity {
                        return Err(RecoveryError::BackupCorrupt);
                    }
                    let (_, reference_name, expected_checksum, expected_length) =
                        consensus::read_current_snapshot_sync(conn, storage_identity)
                            .map_err(|_| RecoveryError::BackupCorrupt)?
                            .ok_or(RecoveryError::BackupCorrupt)?;
                    if reference_name != name {
                        return Err(RecoveryError::BackupCorrupt);
                    }
                    Ok(Some((expected_checksum, expected_length)))
                }
                None => Ok(None),
            }
        },
    )?
    .1;
    match (input.source_snapshot_name, expected_snapshot) {
        (Some(_), Some((expected_checksum, expected_length))) => {
            let staged_file = input.snapshot.file.ok_or(RecoveryError::BackupCorrupt)?;
            staged_file.verify_path_identity(input.snapshot.path)?;
            let (staged_checksum, staged_length) =
                verify_pinned_snapshot_file(staged_file, input.limits.max_snapshot_bytes(), None)?;
            if expected_checksum != staged_checksum || expected_length != staged_length {
                return Err(RecoveryError::BackupCorrupt);
            }
        }
        (None, None) => require_path_absent(input.snapshot.path)?,
        _ => return Err(RecoveryError::BackupCorrupt),
    }
    Ok(())
}

fn same_checkpoint(observed: &RecoveryReplicaEvidence, planned: &RecoveryReplicaEvidence) -> bool {
    observed.replica_token == planned.replica_token
        && observed.backing_identity == planned.backing_identity
        && observed.format == planned.format
        && observed.cluster_digest == planned.cluster_digest
        && observed.configuration_digest == planned.configuration_digest
        && observed.configuration_epoch == planned.configuration_epoch
        && observed.authority_profile == planned.authority_profile
        && observed.fixed_placement_policy == planned.fixed_placement_policy
        && observed.recovery_epoch == planned.recovery_epoch
        && observed.last_plan_digest == planned.last_plan_digest
        && observed.pending_recovery_epoch == planned.pending_recovery_epoch
        && observed.pending_plan_digest == planned.pending_plan_digest
        && observed.watch_cursor_invalidation_floor == planned.watch_cursor_invalidation_floor
        && observed.application_sequence == planned.application_sequence
        && observed.watch_sequence == planned.watch_sequence
        && observed.committed_log_id == planned.committed_log_id
        && observed.applied_log_id == planned.applied_log_id
        && observed.local_head_log_id == planned.local_head_log_id
        && observed.committed_index == planned.committed_index
        && observed.applied_index == planned.applied_index
        && observed.local_head_index == planned.local_head_index
        && observed.branch_digest == planned.branch_digest
        && observed.fence_high_water == planned.fence_high_water
        && observed.credential_high_water == planned.credential_high_water
        && observed.logical_state_digest == planned.logical_state_digest
        && observed.protected_roster_digest == planned.protected_roster_digest
}

struct PreparedSnapshotInstall {
    temporary: PathBuf,
    parent: PathBuf,
    file: PinnedSnapshotFile,
}

/// The destination object admitted before recovery began mutating this
/// replica.  Promotion must be conditional on this exact object: a plain
/// `rename()` after a preflight `stat()` can overwrite a same-byte attacker
/// replacement without ever observing it.
#[derive(Clone, Copy)]
enum PromotionDestination<'a> {
    Absent,
    Present(&'a PinnedSnapshotFile),
}

fn execution_lock_for_path<'a>(
    locks: &'a [ReplicaExecutionLock],
    database: &Path,
) -> Result<&'a ReplicaExecutionLock, RecoveryError> {
    locks
        .iter()
        .find(|lock| lock.path == database)
        .ok_or(RecoveryError::SourceChanged)
}

/// Lock the recovery database inode before it is exchanged into the public
/// namespace.  The fleet execution lock still protects the displaced public
/// inode, so holding this second lock makes the exchange continuous for both
/// names until the workflow has durably recorded the cleanup result.
#[cfg(unix)]
type PreparedDatabaseExecutionLock = nix::fcntl::Flock<File>;

#[cfg(not(unix))]
struct PreparedDatabaseExecutionLock;

#[cfg(unix)]
fn lock_prepared_database(
    prepared: &PinnedSnapshotFile,
) -> Result<PreparedDatabaseExecutionLock, RecoveryError> {
    let lock_file = prepared
        .file
        .try_clone()
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    nix::fcntl::Flock::lock(lock_file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|_| RecoveryError::FileOperationFailed)
}

#[cfg(not(unix))]
fn lock_prepared_database(
    _prepared: &PinnedSnapshotFile,
) -> Result<PreparedDatabaseExecutionLock, RecoveryError> {
    Err(RecoveryError::InvalidRequest)
}

fn pin_promotion_destination(
    destination: &Path,
) -> Result<Option<PinnedSnapshotFile>, RecoveryError> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            let file =
                PinnedSnapshotFile::open(destination).map_err(|_| RecoveryError::SourceChanged)?;
            file.verify_path_identity(destination)
                .map_err(|_| RecoveryError::SourceChanged)?;
            Ok(Some(file))
        }
        Ok(_) => Err(RecoveryError::SourceChanged),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(RecoveryError::SourceChanged),
    }
}

fn promotion_destination_from_pin(
    destination: Option<&PinnedSnapshotFile>,
) -> PromotionDestination<'_> {
    match destination {
        Some(file) => PromotionDestination::Present(file),
        None => PromotionDestination::Absent,
    }
}

fn promotion_disposition(
    key: &RecoveryIntegrityKey,
    promoted: &Path,
    destination: PromotionDestination<'_>,
) -> Result<PromotionDisposition, RecoveryError> {
    match destination {
        PromotionDestination::Absent => {
            require_path_absent(promoted).map_err(|_| RecoveryError::SourceChanged)?;
            Ok(PromotionDisposition::Absent)
        }
        PromotionDestination::Present(file) => {
            file.verify_path_identity(promoted)
                .map_err(|_| RecoveryError::SourceChanged)?;
            Ok(PromotionDisposition::Present {
                displaced_identity: pinned_file_identity(key, file)?,
            })
        }
    }
}

fn promotion_destination_from_workflow(
    key: &RecoveryIntegrityKey,
    promoted: &Path,
    disposition: PromotionDisposition,
) -> Result<Option<PinnedSnapshotFile>, RecoveryError> {
    match disposition {
        PromotionDisposition::Absent => {
            require_path_absent(promoted).map_err(|_| RecoveryError::BackupCorrupt)?;
            Ok(None)
        }
        PromotionDisposition::Present { displaced_identity } => {
            let file = pin_promotion_destination(promoted)
                .map_err(|_| RecoveryError::BackupCorrupt)?
                .ok_or(RecoveryError::BackupCorrupt)?;
            if pinned_file_identity(key, &file)? != displaced_identity {
                return Err(RecoveryError::BackupCorrupt);
            }
            file.verify_path_identity(promoted)
                .map_err(|_| RecoveryError::BackupCorrupt)?;
            Ok(Some(file))
        }
    }
}

/// Copy a staged snapshot into its private temporary name, retaining the
/// exact destination descriptor until that descriptor has been MACed in the
/// workflow.  Promotion is intentionally separate: a crash after this
/// function cannot turn a pathname lookup into evidence on resume.
fn prepare_staged_snapshot(
    target: &RecoveryReplica,
    plan: &RecoveryPlan,
    file_name: &str,
    staged_file: &mut PinnedSnapshotFile,
    staged_snapshot: &Path,
    limits: RecoveryLimits,
    fixed_immutable: bool,
) -> Result<PreparedSnapshotInstall, RecoveryError> {
    validate_snapshot_name(file_name)?;
    let paths = canonical_replica_paths(target, false)?;
    let temporary = snapshot_promotion_temporary_path(target, plan, file_name)?;
    require_path_absent(&temporary)?;
    staged_file.verify_path_identity(staged_snapshot)?;
    let file = copy_snapshot_file_bounded(
        staged_file,
        &temporary,
        limits.max_snapshot_bytes(),
        fixed_immutable,
    )?;
    file.verify_path_identity(&temporary)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    // The temporary name is later authenticated in the workflow. Persist the
    // snapshots-directory entry before that write; otherwise a crash can
    // retain a MAC for an inode which the filesystem never made durable.
    sync_directory(&paths.snapshots)?;
    file.verify_path_identity(&temporary)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    Ok(PreparedSnapshotInstall {
        temporary,
        parent: paths.snapshots,
        file,
    })
}

fn promote_prepared_snapshot(
    target: &RecoveryReplica,
    file_name: &str,
    prepared: PreparedSnapshotInstall,
    destination: PromotionDestination<'_>,
) -> Result<PinnedSnapshotFile, RecoveryError> {
    validate_snapshot_name(file_name)?;
    let promoted = canonical_replica_paths(target, false)?
        .snapshots
        .join(file_name);
    promote_pinned_file(
        prepared.file,
        &prepared.temporary,
        &promoted,
        &prepared.parent,
        destination,
    )
}

/// Promote exactly the inode held by `file`, rather than whichever inode a
/// pathname happens to name after any of the durability boundaries.
fn promote_pinned_file(
    file: PinnedSnapshotFile,
    temporary: &Path,
    promoted: &Path,
    parent: &Path,
    destination: PromotionDestination<'_>,
) -> Result<PinnedSnapshotFile, RecoveryError> {
    #[cfg(test)]
    run_promotion_boundary_hook(PromotionTestBoundary::BeforeRename, temporary);
    file.verify_path_identity(temporary)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    #[cfg(test)]
    run_promotion_boundary_hook(PromotionTestBoundary::BeforeDestinationRename, promoted);
    conditional_promote_pinned_file(&file, temporary, promoted, parent, destination)?;
    #[cfg(test)]
    run_promotion_boundary_hook(PromotionTestBoundary::AfterRename, promoted);
    #[cfg(test)]
    if FAIL_NEXT_PROMOTION_AFTER_RENAME.replace(false) {
        return Err(RecoveryError::InjectedFailure);
    }
    file.verify_path_identity(promoted)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    sync_directory(parent)?;
    #[cfg(test)]
    run_promotion_boundary_hook(PromotionTestBoundary::AfterDirectorySync, promoted);
    file.verify_path_identity(promoted)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    Ok(file)
}

/// Atomically publish `file` only when the destination has the state held at
/// execution-lock acquisition.  Existing targets use `RENAME_EXCHANGE`: the
/// old destination remains reachable at `temporary` and is compared to its
/// held descriptor before the workflow can advance.  An absent destination
/// uses `RENAME_NOREPLACE`, so a late appearance is never overwritten.
#[cfg(target_os = "linux")]
fn conditional_promote_pinned_file(
    file: &PinnedSnapshotFile,
    temporary: &Path,
    promoted: &Path,
    parent: &Path,
    destination: PromotionDestination<'_>,
) -> Result<(), RecoveryError> {
    let directory = File::open(parent).map_err(|_| RecoveryError::FileOperationFailed)?;
    let temporary_name = temporary
        .file_name()
        .ok_or(RecoveryError::FileOperationFailed)?;
    let promoted_name = promoted
        .file_name()
        .ok_or(RecoveryError::FileOperationFailed)?;
    match destination {
        PromotionDestination::Absent => {
            rename_noreplace_in_directory(&directory, temporary_name, promoted_name)
                .map_err(|_| RecoveryError::SourceChanged)
        }
        PromotionDestination::Present(expected) => {
            expected
                .verify_path_identity(promoted)
                .map_err(|_| RecoveryError::SourceChanged)?;
            rename_exchange_in_directory(&directory, temporary_name, promoted_name)
                .map_err(|_| RecoveryError::FileOperationFailed)?;
            if expected.verify_path_identity(temporary).is_err() {
                // The exchange retained the unexpected object at
                // `temporary`.  Best-effort rollback preserves it at the
                // public destination rather than reporting an error after
                // silently installing our recovery copy over a replacement.
                if file.verify_path_identity(promoted).is_ok() {
                    let _ = rename_exchange_in_directory(&directory, temporary_name, promoted_name);
                }
                return Err(RecoveryError::SourceChanged);
            }
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn conditional_promote_pinned_file(
    _file: &PinnedSnapshotFile,
    _temporary: &Path,
    _promoted: &Path,
    _parent: &Path,
    _destination: PromotionDestination<'_>,
) -> Result<(), RecoveryError> {
    Err(RecoveryError::InvalidRequest)
}

/// Recover the completed half of an exchange-style promotion before looking
/// at its temporary name.  `RENAME_EXCHANGE` deliberately leaves the old
/// destination at `temporary`; a crash in that small window must not mistake
/// the displaced old inode for the workflow-MACed prepared inode and retry
/// over the newly installed object.
///
/// The displaced inode is intentionally retained here. The caller still owns
/// the authenticated workflow cleanup journal and must reconcile it before
/// removing that journal. Keeping this classifier side-effect free lets a
/// retry distinguish a completed exchange from an unpromoted temporary.
fn open_completed_promotion_from_workflow(
    key: &RecoveryIntegrityKey,
    temporary: &Path,
    promoted: &Path,
    parent: &Path,
    expected_identity: RecoveryDigest,
    disposition: PromotionDisposition,
) -> Result<Option<PinnedSnapshotFile>, RecoveryError> {
    let promoted_metadata = match fs::symlink_metadata(promoted) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(RecoveryError::BackupCorrupt),
    };
    if !promoted_metadata.file_type().is_file() {
        return Err(RecoveryError::BackupCorrupt);
    }
    let file = PinnedSnapshotFile::open(promoted).map_err(|_| RecoveryError::BackupCorrupt)?;
    if pinned_file_identity(key, &file)? != expected_identity {
        return Ok(None);
    }
    file.verify_path_identity(promoted)
        .map_err(|_| RecoveryError::BackupCorrupt)?;

    let displaced = match disposition {
        PromotionDisposition::Present { displaced_identity } => {
            match open_promotion_temporary_if_present(temporary)? {
                Some(displaced) => {
                    if pinned_file_identity(key, &displaced)? != displaced_identity {
                        return Err(RecoveryError::BackupCorrupt);
                    }
                    displaced
                        .verify_path_identity(temporary)
                        .map_err(|_| RecoveryError::BackupCorrupt)?;
                    Some(displaced)
                }
                // A crash can follow the authenticated cleanup unlink but
                // precede the next workflow write. The public name remains
                // proven above, and the completion reconciliation will sync
                // and re-prove this already-absent journal entry before
                // advancing the workflow.
                None => None,
            }
        }
        PromotionDisposition::Absent => match fs::symlink_metadata(temporary) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            _ => return Err(RecoveryError::BackupCorrupt),
        },
    };

    // The first process can have died after the namespace exchange but before
    // syncing this parent.  Persist and then re-prove both names while their
    // pins are retained before returning an installed object to the workflow
    // state transition.
    sync_directory(parent).map_err(|_| RecoveryError::BackupCorrupt)?;
    file.verify_path_identity(promoted)
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    if let Some(displaced) = displaced.as_ref() {
        displaced
            .verify_path_identity(temporary)
            .map_err(|_| RecoveryError::BackupCorrupt)?;
    }
    Ok(Some(file))
}

/// Open a journaled temporary only when it is a regular, nofollow object.
/// A missing name is the idempotent replay state after authenticated cleanup;
/// every other failure is malformed namespace state, never absence.
fn open_promotion_temporary_if_present(
    temporary: &Path,
) -> Result<Option<PinnedSnapshotFile>, RecoveryError> {
    match fs::symlink_metadata(temporary) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            PinnedSnapshotFile::open(temporary)
                .map(Some)
                .map_err(|_| RecoveryError::BackupCorrupt)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Ok(_) | Err(_) => Err(RecoveryError::BackupCorrupt),
    }
}

/// Reconcile the exact namespace outcome recorded by a promotion journal.
///
/// `installed` is the semantically verified public inode. The workflow still
/// authenticates both that inode and the destination disposition while this
/// function runs: it may remove only the exact displaced inode, via a
/// nofollow parent-directory descriptor, and only then may its caller erase
/// the journal in a separately durable workflow transition.
#[cfg(unix)]
fn reconcile_completed_promotion_cleanup(
    key: &RecoveryIntegrityKey,
    temporary: &Path,
    promoted: &Path,
    parent: &Path,
    expected_identity: RecoveryDigest,
    disposition: PromotionDisposition,
    installed: &PinnedSnapshotFile,
) -> Result<(), RecoveryError> {
    use rustix::fs::{statat, unlinkat, AtFlags};

    let temporary_name = temporary.file_name().ok_or(RecoveryError::BackupCorrupt)?;
    if temporary.parent() != Some(parent)
        || promoted.parent() != Some(parent)
        || !matches!(
            Path::new(temporary_name).components().next(),
            Some(std::path::Component::Normal(_))
        )
        || Path::new(temporary_name).components().nth(1).is_some()
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    if pinned_file_identity(key, installed)? != expected_identity {
        return Err(RecoveryError::BackupCorrupt);
    }
    installed
        .verify_path_identity(promoted)
        .map_err(|_| RecoveryError::BackupCorrupt)?;

    let directory = open_directory(parent).map_err(|_| RecoveryError::BackupCorrupt)?;
    match disposition {
        PromotionDisposition::Present { displaced_identity } => {
            if let Some(displaced) = open_promotion_temporary_if_present(temporary)? {
                if pinned_file_identity(key, &displaced)? != displaced_identity {
                    return Err(RecoveryError::BackupCorrupt);
                }
                displaced
                    .verify_path_identity(temporary)
                    .map_err(|_| RecoveryError::BackupCorrupt)?;
                // Keep both pins live while unlinking through the exact
                // nofollow parent descriptor. Cooperating SDK publishers
                // are excluded by the recovery latch/execution locks.
                installed
                    .verify_path_identity(promoted)
                    .map_err(|_| RecoveryError::BackupCorrupt)?;
                unlinkat(&directory, temporary_name, AtFlags::empty())
                    .map_err(|_| RecoveryError::BackupCorrupt)?;
            } else {
                // The prior process may have completed the unlink but died
                // before the parent fsync or workflow write. That is the only
                // idempotent replay state admitted for a Present journal.
            }
        }
        PromotionDisposition::Absent => {
            match statat(&directory, temporary_name, AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => {}
                Ok(_) | Err(_) => return Err(RecoveryError::BackupCorrupt),
            }
        }
    }

    directory
        .sync_all()
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    installed
        .verify_path_identity(promoted)
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    match statat(&directory, temporary_name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Ok(_) | Err(_) => Err(RecoveryError::BackupCorrupt),
    }
}

#[cfg(not(unix))]
fn reconcile_completed_promotion_cleanup(
    _key: &RecoveryIntegrityKey,
    _temporary: &Path,
    _promoted: &Path,
    _parent: &Path,
    _expected_identity: RecoveryDigest,
    _disposition: PromotionDisposition,
    _installed: &PinnedSnapshotFile,
) -> Result<(), RecoveryError> {
    Err(RecoveryError::InvalidRequest)
}

fn promote_prepared_snapshot_from_workflow(
    key: &RecoveryIntegrityKey,
    target: &RecoveryReplica,
    plan: &RecoveryPlan,
    file_name: &str,
    expected_identity: RecoveryDigest,
    disposition: PromotionDisposition,
) -> Result<PinnedSnapshotFile, RecoveryError> {
    validate_snapshot_name(file_name)?;
    let paths = canonical_replica_paths(target, false)?;
    let temporary = snapshot_promotion_temporary_path(target, plan, file_name)?;
    let promoted = paths.snapshots.join(file_name);
    if let Some(file) = open_completed_promotion_from_workflow(
        key,
        &temporary,
        &promoted,
        &paths.snapshots,
        expected_identity,
        disposition,
    )? {
        return Ok(file);
    }
    match fs::symlink_metadata(&temporary) {
        Ok(_) => {
            let file =
                PinnedSnapshotFile::open(&temporary).map_err(|_| RecoveryError::BackupCorrupt)?;
            if pinned_file_identity(key, &file)? != expected_identity {
                return Err(RecoveryError::BackupCorrupt);
            }
            file.verify_path_identity(&temporary)
                .map_err(|_| RecoveryError::BackupCorrupt)?;
            let destination_pin = promotion_destination_from_workflow(key, &promoted, disposition)?;
            promote_prepared_snapshot(
                target,
                file_name,
                PreparedSnapshotInstall {
                    temporary,
                    parent: paths.snapshots,
                    file,
                },
                promotion_destination_from_pin(destination_pin.as_ref()),
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A crash can happen after rename but before the workflow state
            // transition.  The only acceptable promoted object is the inode
            // already committed as the temporary identity; any content-only
            // clone is rejected here.
            let file =
                PinnedSnapshotFile::open(&promoted).map_err(|_| RecoveryError::BackupCorrupt)?;
            if pinned_file_identity(key, &file)? != expected_identity {
                return Err(RecoveryError::BackupCorrupt);
            }
            file.verify_path_identity(&promoted)
                .map_err(|_| RecoveryError::BackupCorrupt)?;
            // The previous process may have died after rename but before its
            // parent-directory fsync. Make that promoted dentry durable under
            // this held descriptor before the caller can MAC SnapshotInstalled.
            sync_directory(&paths.snapshots).map_err(|_| RecoveryError::BackupCorrupt)?;
            file.verify_path_identity(&promoted)
                .map_err(|_| RecoveryError::BackupCorrupt)?;
            Ok(file)
        }
        Err(_) => Err(RecoveryError::BackupCorrupt),
    }
}

fn require_snapshot_install_temporary_absent(
    target: &RecoveryReplica,
    plan: &RecoveryPlan,
    file_name: Option<&str>,
) -> Result<(), RecoveryError> {
    let Some(file_name) = file_name else {
        return Ok(());
    };
    validate_snapshot_name(file_name)?;
    require_path_absent(&snapshot_promotion_temporary_path(target, plan, file_name)?)
}

fn remove_snapshot_install_temporary_if_present(
    target: &RecoveryReplica,
    plan: &RecoveryPlan,
    file_name: &str,
) -> Result<(), RecoveryError> {
    remove_regular_file_if_present(&snapshot_promotion_temporary_path(target, plan, file_name)?)
}

/// Completed exchanges retain a displaced snapshot at their temporary name.
/// Keep that quarantine inode separate for every target, plan and destination
/// name without concatenating the caller-controlled snapshot filename into a
/// single filesystem component.
fn snapshot_promotion_temporary_path(
    target: &RecoveryReplica,
    plan: &RecoveryPlan,
    file_name: &str,
) -> Result<PathBuf, RecoveryError> {
    validate_snapshot_name(file_name)?;
    let paths = canonical_replica_paths(target, false)?;
    snapshot_promotion_temporary_path_for(
        &paths.snapshots,
        target.replica_id.as_str(),
        plan.plan_digest,
        file_name,
    )
}

#[cfg(test)]
pub(super) fn snapshot_promotion_temporary_path_for_test(
    target: &RecoveryReplica,
    plan: &RecoveryPlan,
    file_name: &str,
) -> Result<PathBuf, RecoveryError> {
    snapshot_promotion_temporary_path(target, plan, file_name)
}

fn snapshot_promotion_temporary_path_for(
    snapshots: &Path,
    replica_id: &str,
    plan_digest: RecoveryDigest,
    file_name: &str,
) -> Result<PathBuf, RecoveryError> {
    validate_snapshot_name(file_name)?;
    let target_component =
        RecoveryDigest::from_bytes(Sha256::digest(replica_id.as_bytes()).into()).to_hex();
    let snapshot_component =
        RecoveryDigest::from_bytes(Sha256::digest(file_name.as_bytes()).into()).to_hex();
    Ok(snapshots.join(format!(
        "recovery-{}-{}-{}.part",
        plan_digest.to_hex(),
        &target_component[..16],
        &snapshot_component[..16],
    )))
}

/// Verify target snapshot bytes/profile through the exact installed
/// descriptor and return that descriptor to the caller.  Callers use the
/// returned pin for the workflow inode commitment instead of reopening the
/// promoted pathname.
fn open_verified_installed_snapshot(
    target: &RecoveryReplica,
    file_name: &str,
    staged_file: &mut PinnedSnapshotFile,
    staged_snapshot: &Path,
    limits: RecoveryLimits,
    fixed_immutable: bool,
) -> Result<PinnedSnapshotFile, RecoveryError> {
    validate_snapshot_name(file_name)?;
    let paths = canonical_replica_paths(target, false)?;
    staged_file.verify_path_identity(staged_snapshot)?;
    let installed = paths.snapshots.join(file_name);
    let mut installed_file = PinnedSnapshotFile::open(&installed)?;
    if fixed_immutable {
        measure_fixed_snapshot_file(staged_file)?;
        measure_fixed_snapshot_file(&installed_file)?;
    }
    let expected = verify_pinned_snapshot_file(staged_file, limits.max_snapshot_bytes(), None)?;
    let observed =
        verify_pinned_snapshot_file(&mut installed_file, limits.max_snapshot_bytes(), None)?;
    installed_file.verify_path_identity(&installed)?;
    if observed != expected {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(installed_file)
}

fn verify_snapshot_matches_staged(
    staged_file: &mut PinnedSnapshotFile,
    staged_snapshot: &Path,
    installed_file: &mut PinnedSnapshotFile,
    installed_path: &Path,
    limits: RecoveryLimits,
    fixed_immutable: bool,
) -> Result<(), RecoveryError> {
    staged_file.verify_path_identity(staged_snapshot)?;
    installed_file.verify_path_identity(installed_path)?;
    if fixed_immutable {
        measure_fixed_snapshot_file(staged_file)?;
        measure_fixed_snapshot_file(installed_file)?;
    }
    let expected = verify_pinned_snapshot_file(staged_file, limits.max_snapshot_bytes(), None)?;
    let observed = verify_pinned_snapshot_file(installed_file, limits.max_snapshot_bytes(), None)?;
    if observed != expected {
        return Err(RecoveryError::BackupCorrupt);
    }
    installed_file.verify_path_identity(installed_path)?;
    Ok(())
}

fn target_matches_staged_recovery(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    target: &RecoveryReplica,
    target_database: &PinnedSnapshotFile,
    staged: &PinnedSnapshotFile,
    limits: RecoveryLimits,
) -> Result<bool, RecoveryError> {
    // The staged database was authenticated through this descriptor before
    // recovery began.  Reopening `staged.sqlite` here would make a
    // byte-identical pathname substitution authoritative after that fact.
    let staged = open_read_only_pinned(staged)?;
    let (staged_epoch, _, staged_key) =
        ops::read_restore_scan_state_sync(&staged).map_err(|_| RecoveryError::CorruptReplica)?;
    match inspect_replica_from_pinned_with(
        InspectionInput {
            key,
            replica: target,
            identity: plan.body.identity,
            expected_members: &plan.body.expected_members,
            limits,
        },
        canonical_replica_paths(target, false)?,
        target_database,
        None,
        |evidence, conn| {
            if verify_target_installed_evidence(plan, evidence).is_err() {
                return Ok(None);
            }
            let (target_epoch, _, target_key) = ops::read_restore_scan_state_sync(conn)
                .map_err(|_| RecoveryError::CorruptReplica)?;
            Ok(Some((target_epoch, target_key)))
        },
    ) {
        Ok((_evidence, Some((target_epoch, target_key)))) => {
            Ok(target_epoch != staged_epoch && *target_key != *staged_key)
        }
        // Match the old installed predicate behavior: an invalid target is a
        // non-match that fails the workflow closed at its caller.  Crucially,
        // no fallback pathname open is allowed after this point.
        Ok((_, None)) | Err(_) => Ok(false),
    }
}

/// The immediate post-promotion proof must inspect the inode that was copied
/// and renamed, not a second lookup of the target pathname.  The workflow
/// write below is therefore bound to this held descriptor.
fn verify_target_installed_from_pinned(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    target: &RecoveryReplica,
    database: &PinnedSnapshotFile,
    limits: RecoveryLimits,
) -> Result<(), RecoveryError> {
    let paths = canonical_replica_paths(target, false)?;
    database
        .verify_path_identity(&paths.database)
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    inspect_replica_from_pinned_with(
        InspectionInput {
            key,
            replica: target,
            identity: plan.body.identity,
            expected_members: &plan.body.expected_members,
            limits,
        },
        paths,
        database,
        None,
        |evidence, _conn| verify_target_installed_evidence(plan, evidence),
    )?;
    Ok(())
}

fn verify_target_installed_evidence(
    plan: &RecoveryPlan,
    evidence: &RecoveryReplicaEvidence,
) -> Result<(), RecoveryError> {
    let planned_source = plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == plan.body.source_token)
        .ok_or(RecoveryError::StalePlan)?;
    if evidence.pending_recovery_epoch != Some(plan.body.next_recovery_epoch)
        || evidence.pending_plan_digest != Some(plan.plan_digest)
        || evidence.application_sequence != plan.body.application_sequence_high_water
        || evidence.watch_sequence != plan.body.watch_cursor_invalidation_floor
        || evidence.watch_cursor_invalidation_floor != plan.body.watch_cursor_invalidation_floor
        || evidence.logical_state_digest != planned_source.logical_state_digest
        || evidence.recovery_v2_invariant_state_digest
            != planned_source.recovery_v2_invariant_state_digest
        || evidence.authority_profile != plan.body.source_authority_profile
        || evidence.fixed_placement_policy != plan.body.source_fixed_placement_policy
        || evidence.protected_roster_digest != plan.body.source_protected_roster_digest
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(())
}

/// The installed predecessor of an explicit legacy recovery is created only
/// after the original plan has been executed.  Its durable OpenRaft baseline
/// is therefore absent from the legacy plan and must instead match the
/// descriptor-bound capsule MACed into the workflow before V2 proposal.
fn verify_legacy_target_installed_evidence(
    plan: &RecoveryPlan,
    evidence: &RecoveryReplicaEvidence,
    predecessor: &FinalizationPredecessorCapsule,
) -> Result<(), RecoveryError> {
    let baseline = predecessor.baseline_log_id;
    if evidence.pending_recovery_epoch != Some(plan.body.next_recovery_epoch)
        || evidence.pending_plan_digest != Some(plan.plan_digest)
        || evidence.recovery_epoch != predecessor.recovery_epoch
        || evidence.last_plan_digest != predecessor.last_plan_digest
        || evidence.watch_cursor_invalidation_floor != predecessor.watch_cursor_invalidation_floor
        || evidence.application_sequence != predecessor.application_sequence
        || evidence.machine_last_digest != predecessor.machine_last_digest
        || evidence.machine_logical_time != predecessor.machine_logical_time
        || evidence.watch_sequence != predecessor.watch_sequence
        || evidence.authority_commitment != predecessor.authority_commitment
        || evidence.recovery_v2_invariant_state_digest
            != predecessor.recovery_v2_invariant_state_digest
        || evidence.applied_log_id != Some(baseline)
        || evidence.finalize_log_id.is_some()
        || evidence.authority_profile != plan.body.source_authority_profile
        || evidence.fixed_placement_policy != plan.body.source_fixed_placement_policy
        || evidence.protected_roster_digest != plan.body.source_protected_roster_digest
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(())
}

fn verify_target_finalized_from_pinned(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    target: &RecoveryReplica,
    database: &PinnedSnapshotFile,
    limits: RecoveryLimits,
    legacy_predecessor: Option<&FinalizationPredecessorCapsule>,
) -> Result<(), RecoveryError> {
    let paths = canonical_replica_paths(target, false)?;
    database
        .verify_path_identity(&paths.database)
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    inspect_replica_from_pinned_with(
        InspectionInput {
            key,
            replica: target,
            identity: plan.body.identity,
            expected_members: &plan.body.expected_members,
            limits,
        },
        paths,
        database,
        None,
        |evidence, conn| {
            verify_target_finalized_evidence(plan, evidence, conn, limits, legacy_predecessor)
        },
    )?;
    Ok(())
}

fn verify_target_finalized_evidence(
    plan: &RecoveryPlan,
    evidence: &RecoveryReplicaEvidence,
    conn: &Connection,
    limits: RecoveryLimits,
    legacy_predecessor: Option<&FinalizationPredecessorCapsule>,
) -> Result<(), RecoveryError> {
    verify_exact_finalized_recovery_v2(
        plan,
        evidence,
        conn,
        limits,
        FinalizedRecoveryV2ProofPhase::PreTerminalStrict,
        legacy_predecessor,
        None,
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FinalizedRecoveryV2ProofPhase {
    /// The Active latch still fences ordinary traffic. The exact V2 marker is
    /// the only Normal command allowed after baseline.
    PreTerminalStrict,
    /// A durable common terminal proof exists and at least one fleet member
    /// has reached Consumed, with every other member PendingHandoff or
    /// Consumed. Pending remains closed to readiness, but another consumed
    /// voter may already have admitted legitimate replicated traffic here;
    /// authenticate the historical V2 marker/outcome instead of treating that
    /// traffic as recovery corruption.
    PostTerminalHistorical,
}

/// Prove the historical V2 effect itself instead of merely accepting a
/// current recovery counter that is at least the requested value.  A later
/// ordinary command may legitimately advance the machine, so the proof is
/// anchored to the persisted full finalization LogId, retained exact command,
/// and its one request outcome.  `PreTerminalStrict` prevents compaction of
/// that marker while every sidecar remains Active, so a compacted marker is
/// not interchangeable evidence there.  The narrowly authenticated
/// `PostTerminalHistorical` exception instead requires the exact terminal
/// proof plus matching certificate, outcome, purge, and snapshot evidence.
fn verify_exact_finalized_recovery_v2(
    plan: &RecoveryPlan,
    evidence: &RecoveryReplicaEvidence,
    conn: &Connection,
    limits: RecoveryLimits,
    phase: FinalizedRecoveryV2ProofPhase,
    legacy_predecessor: Option<&FinalizationPredecessorCapsule>,
    terminal_proof: Option<&RecoveryTerminalProofV1>,
) -> Result<(), RecoveryError> {
    let predecessor = legacy_predecessor
        .cloned()
        .map(Ok)
        .unwrap_or_else(|| finalization_predecessor_from_plan(plan))?;
    let finalize_log_id = evidence
        .finalize_log_id
        .ok_or(RecoveryError::BackupCorrupt)?;
    let committed = evidence
        .committed_log_id
        .ok_or(RecoveryError::BackupCorrupt)?;
    let applied = evidence
        .applied_log_id
        .ok_or(RecoveryError::BackupCorrupt)?;
    let recovery_sequence = plan
        .body
        .application_sequence_high_water
        .checked_add(1)
        .ok_or(RecoveryError::BackupCorrupt)?;
    if evidence.recovery_epoch != plan.body.next_recovery_epoch
        || evidence.last_plan_digest != plan.plan_digest
        || evidence.pending_recovery_epoch.is_some()
        || evidence.pending_plan_digest.is_some()
        || evidence.watch_cursor_invalidation_floor != plan.body.watch_cursor_invalidation_floor
        || evidence.authority_profile != plan.body.source_authority_profile
        || evidence.fixed_placement_policy != plan.body.source_fixed_placement_policy
        || !full_log_id_not_after(&finalize_log_id, &committed)
        || !full_log_id_not_after(&finalize_log_id, &applied)
        || (matches!(phase, FinalizedRecoveryV2ProofPhase::PreTerminalStrict)
            && (evidence.protected_roster_digest != plan.body.source_protected_roster_digest
                || evidence.authority_commitment != predecessor.authority_commitment))
    {
        return Err(RecoveryError::BackupCorrupt);
    }

    let expected_request_id = recovery_v2_request_id(plan);
    let expected_intent = recovery_v2_intent_from_predecessor(plan, &predecessor);
    let payload_digest = RecoveryDigest::from_bytes(
        consensus::operator_recovery_v2_payload_digest_sync(
            plan.body.identity,
            &SessionMutationIntent::FinalizeOperatorRecoveryV2(Box::new(expected_intent.clone())),
        )
        .map_err(|_| RecoveryError::BackupCorrupt)?,
    );
    if let Some(proof) = terminal_proof {
        validate_terminal_proof_header(
            proof,
            plan,
            &predecessor,
            &finalize_log_id,
            expected_request_id,
            payload_digest,
        )?;
    } else if matches!(phase, FinalizedRecoveryV2ProofPhase::PostTerminalHistorical) {
        // A consumed sidecar can only be interpreted through the durable
        // common proof written before the first release.  Never turn an old
        // workflow state or another replica's marker into fallback evidence.
        return Err(RecoveryError::BackupCorrupt);
    }
    let retained_command = match phase {
        FinalizedRecoveryV2ProofPhase::PreTerminalStrict => strict_recovery_v2_suffix(
            conn,
            plan.body.identity,
            &predecessor.baseline_log_id,
            &finalize_log_id,
            evidence
                .local_head_log_id
                .as_ref()
                .ok_or(RecoveryError::BackupCorrupt)?,
            expected_request_id,
            &expected_intent,
            limits,
        )?,
        FinalizedRecoveryV2ProofPhase::PostTerminalHistorical => {
            match retained_recovery_v2_marker(
                conn,
                plan.body.identity,
                &finalize_log_id,
                expected_request_id,
                &expected_intent,
            ) {
                Ok(command) => command,
                Err(_) => {
                    let proof = terminal_proof.ok_or(RecoveryError::BackupCorrupt)?;
                    let compacted = verify_compacted_terminal_proof(
                        conn,
                        plan,
                        proof,
                        &finalize_log_id,
                        payload_digest,
                    );
                    compacted?;
                    // The proof retains the original leader-owned command
                    // time, so it is sufficient to reconstruct the exact V2
                    // command semantics after legitimate compaction.
                    let historical = verify_historical_finalized_state(
                        plan,
                        evidence,
                        conn,
                        &predecessor,
                        proof,
                    );
                    return historical;
                }
            }
        }
    };
    if terminal_proof
        .is_some_and(|proof| proof.original_command_logical_time != retained_command.logical_time)
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    let expected_logical_time = predecessor
        .machine_logical_time
        .map_or(retained_command.logical_time, |last| {
            last.max(retained_command.logical_time)
        });
    let previous =
        SessionConsensusEntryDigest::from_bytes(predecessor.machine_last_digest.as_bytes());
    let expected_digest = retained_command
        .calculate_applied_digest(recovery_sequence, previous, expected_logical_time)
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    let certificate_outcome = verified_finalize_certificate_outcome(
        conn,
        plan.body.identity,
        &finalize_log_id,
        expected_request_id,
        payload_digest,
        retained_command.logical_time,
        recovery_sequence,
        expected_digest,
        expected_logical_time,
    )?;
    let outcome = consensus::exact_operator_recovery_v2_outcome_sync(
        conn,
        plan.body.identity,
        expected_request_id,
        payload_digest.as_bytes(),
        &finalize_log_id,
        recovery_sequence,
        expected_digest,
        expected_logical_time,
    )
    .map_err(|_| RecoveryError::BackupCorrupt)?
    .ok_or(RecoveryError::BackupCorrupt)?;
    if terminal_outcome_commitment(&outcome)? != terminal_outcome_commitment(&certificate_outcome)?
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    if let Some(proof) = terminal_proof {
        if proof.recovery_application_sequence != recovery_sequence
            || proof.effective_logical_time != expected_logical_time
            || proof.applied_digest != RecoveryDigest::from_bytes(*expected_digest.as_bytes())
            || proof.outcome_commitment != terminal_outcome_commitment(&outcome)?
        {
            return Err(RecoveryError::BackupCorrupt);
        }
    }
    match phase {
        // Before a durable Consumed terminal record permits traffic, an exact
        // V2 marker is the complete state-machine transition.  Any higher
        // mutable counter or changed machine digest therefore proves an
        // unaccounted command and must fail closed.
        FinalizedRecoveryV2ProofPhase::PreTerminalStrict
            if evidence.application_sequence != recovery_sequence
                || evidence.watch_sequence != plan.body.watch_cursor_invalidation_floor
                // `observed_*_high_water_sync` reports allocator `next - 1`.
                // V2 advances the allocator to the planned high-water plus
                // one, so its exact observable post-state is the planned
                // high-water itself.
                || evidence.fence_high_water != plan.body.fence_high_water
                || evidence.credential_high_water != plan.body.credential_high_water
                || evidence.machine_last_digest
                    != RecoveryDigest::from_bytes(*expected_digest.as_bytes())
                || evidence.machine_logical_time != Some(expected_logical_time)
                || evidence.recovery_v2_invariant_state_digest
                    != predecessor.recovery_v2_invariant_state_digest
                || !recovery_v2_exact_lease_postconditions(
                    conn,
                    plan.body.fence_high_water,
                    plan.body.credential_high_water,
                )? =>
        {
            return Err(RecoveryError::BackupCorrupt);
        }
        // Once the durable common proof exists and this replica is terminal
        // Pending or Consumed, another consumed voter may have replicated
        // legitimate traffic here. Keep the exact historical marker/outcome
        // proof above, but do not falsely reject that traffic.
        FinalizedRecoveryV2ProofPhase::PostTerminalHistorical
            if evidence.application_sequence < recovery_sequence
                || evidence.watch_sequence < plan.body.watch_cursor_invalidation_floor
                || evidence.fence_high_water < plan.body.fence_high_water
                || evidence.credential_high_water < plan.body.credential_high_water =>
        {
            return Err(RecoveryError::BackupCorrupt);
        }
        _ => {}
    }
    Ok(())
}

fn validate_terminal_proof_header(
    proof: &RecoveryTerminalProofV1,
    plan: &RecoveryPlan,
    predecessor: &FinalizationPredecessorCapsule,
    finalize_log_id: &LogId<SessionConsensusNodeId>,
    request_id: SessionConsensusRequestId,
    payload_digest: RecoveryDigest,
) -> Result<(), RecoveryError> {
    if proof.proof_revision != RECOVERY_TERMINAL_PROOF_REVISION
        || proof.proof_domain != RECOVERY_TERMINAL_PROOF_DOMAIN
        || proof.identity != plan.body.identity
        || proof.recovery_epoch != plan.body.next_recovery_epoch
        || proof.plan_digest != plan.plan_digest
        || proof.predecessor != *predecessor
        || proof.finalize_log_id != *finalize_log_id
        || proof.command_schema_version != SESSION_CONSENSUS_SCHEMA_VERSION
        || proof.request_id != request_id
        || proof.intent_payload_digest != payload_digest
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(())
}

fn terminal_outcome_commitment(
    outcome: &crate::consensus::SessionConsensusResponse,
) -> Result<RecoveryDigest, RecoveryError> {
    let encoded = serde_json::to_vec(outcome).map_err(|_| RecoveryError::BackupCorrupt)?;
    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_TERMINAL_OUTCOME_DOMAIN);
    hasher.update(encoded);
    Ok(RecoveryDigest::from_bytes(hasher.finalize().into()))
}

/// Join the workflow HMAC proof to the independently durable V2 certificate.
/// The workflow remains the terminal handoff authority; the certificate is
/// the compact replay authority and must reconstruct exactly the same
/// original command/effect before either retained or historical evidence is
/// accepted.
#[allow(clippy::too_many_arguments)] // Independently authenticated certificate fields.
fn verified_finalize_certificate_outcome(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    finalize_log_id: &LogId<SessionConsensusNodeId>,
    request_id: SessionConsensusRequestId,
    payload_digest: RecoveryDigest,
    original_command_logical_time: Timestamp,
    recovery_application_sequence: u64,
    applied_digest: SessionConsensusEntryDigest,
    effective_logical_time: Timestamp,
) -> Result<crate::consensus::SessionConsensusResponse, RecoveryError> {
    let certificate =
        consensus::operator_recovery_v2_finalize_certificate_binding_sync(conn, identity)
            .map_err(|_| RecoveryError::BackupCorrupt)?
            .ok_or(RecoveryError::BackupCorrupt)?;
    let response = certificate.response;
    if certificate.finalize_log_id != *finalize_log_id
        || certificate.request_id != request_id
        || RecoveryDigest::from_bytes(certificate.payload_digest) != payload_digest
        || certificate.original_command_logical_time != original_command_logical_time
        || !matches!(response.result, Ok(SessionMutationOutcome::Unit))
        || response.sequence != recovery_application_sequence
        || response.digest != Some(applied_digest)
        || response.logical_time != Some(effective_logical_time)
        || response.raft_log_index != finalize_log_id.index
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(response)
}

/// Validate compacted historical evidence through the descriptor-bound read
/// transaction established by `open_read_only_pinned`. This is reachable only
/// for authenticated post-terminal history: the pre-terminal strict phase
/// rejects a missing/compacted V2 marker rather than treating it as proof. A
/// post-terminal marker is admissible only when both the exact full purge
/// floor and the selected snapshot lineage cover it; a same-index,
/// different-term value never satisfies `full_log_id_not_after`.
fn verify_compacted_terminal_proof(
    conn: &Connection,
    plan: &RecoveryPlan,
    proof: &RecoveryTerminalProofV1,
    finalize_log_id: &LogId<SessionConsensusNodeId>,
    payload_digest: RecoveryDigest,
) -> Result<(), RecoveryError> {
    let recovery = consensus::read_operator_recovery_sync(conn, plan.body.identity)
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    if recovery.recovery_epoch != plan.body.next_recovery_epoch
        || RecoveryDigest::from_bytes(recovery.last_plan_digest) != plan.plan_digest
        || recovery.pending_epoch.is_some()
        || recovery.pending_plan_digest.is_some()
        || recovery.finalize_log_id != Some(*finalize_log_id)
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    let purged = consensus::read_purged_sync(conn, plan.body.identity)
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    let snapshot = consensus::read_current_snapshot_sync(conn, plan.body.identity)
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    let snapshot_log = snapshot
        .as_ref()
        .and_then(|(meta, _, _, _)| meta.last_log_id.as_ref())
        .ok_or(RecoveryError::BackupCorrupt)?;
    require_compacted_terminal_log_lineage(finalize_log_id, purged.as_ref(), snapshot_log)?;
    let previous =
        SessionConsensusEntryDigest::from_bytes(proof.predecessor.machine_last_digest.as_bytes());
    let recomputed_effective = proof
        .predecessor
        .machine_logical_time
        .map_or(proof.original_command_logical_time, |last| {
            last.max(proof.original_command_logical_time)
        });
    let recomputed_digest = crate::consensus::SessionConsensusCommand {
        schema_version: proof.command_schema_version,
        identity: proof.identity,
        request_id: proof.request_id,
        logical_time: proof.original_command_logical_time,
        intent: SessionMutationIntent::FinalizeOperatorRecoveryV2(Box::new(
            recovery_v2_intent_from_predecessor(plan, &proof.predecessor),
        )),
    }
    .calculate_applied_digest(
        proof.recovery_application_sequence,
        previous,
        recomputed_effective,
    )
    .map_err(|_| RecoveryError::BackupCorrupt)?;
    if proof.effective_logical_time != recomputed_effective
        || proof.applied_digest != RecoveryDigest::from_bytes(*recomputed_digest.as_bytes())
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    let certificate_outcome = verified_finalize_certificate_outcome(
        conn,
        plan.body.identity,
        finalize_log_id,
        proof.request_id,
        payload_digest,
        proof.original_command_logical_time,
        proof.recovery_application_sequence,
        recomputed_digest,
        recomputed_effective,
    )?;
    let outcome = consensus::exact_operator_recovery_v2_outcome_sync(
        conn,
        plan.body.identity,
        proof.request_id,
        payload_digest.as_bytes(),
        finalize_log_id,
        proof.recovery_application_sequence,
        recomputed_digest,
        recomputed_effective,
    )
    .map_err(|_| RecoveryError::BackupCorrupt)?
    .ok_or(RecoveryError::BackupCorrupt)?;
    if proof.outcome_commitment != terminal_outcome_commitment(&outcome)?
        || terminal_outcome_commitment(&outcome)?
            != terminal_outcome_commitment(&certificate_outcome)?
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(())
}

fn verify_historical_finalized_state(
    plan: &RecoveryPlan,
    evidence: &RecoveryReplicaEvidence,
    conn: &Connection,
    predecessor: &FinalizationPredecessorCapsule,
    proof: &RecoveryTerminalProofV1,
) -> Result<(), RecoveryError> {
    let recovery_sequence = plan
        .body
        .application_sequence_high_water
        .checked_add(1)
        .ok_or(RecoveryError::BackupCorrupt)?;
    if proof.recovery_application_sequence != recovery_sequence
        || evidence.application_sequence < recovery_sequence
        || evidence.watch_sequence < plan.body.watch_cursor_invalidation_floor
        || evidence.fence_high_water < plan.body.fence_high_water
        || evidence.credential_high_water < plan.body.credential_high_water
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    let payload_digest = RecoveryDigest::from_bytes(
        consensus::operator_recovery_v2_payload_digest_sync(
            plan.body.identity,
            &SessionMutationIntent::FinalizeOperatorRecoveryV2(Box::new(
                recovery_v2_intent_from_predecessor(plan, predecessor),
            )),
        )
        .map_err(|_| RecoveryError::BackupCorrupt)?,
    );
    verify_compacted_terminal_proof(conn, plan, proof, &proof.finalize_log_id, payload_digest)
}

pub(super) fn full_log_id_not_after(
    earlier: &LogId<SessionConsensusNodeId>,
    later: &LogId<SessionConsensusNodeId>,
) -> bool {
    // A full LogId is not a lexicographically ordered `(term, index)` pair.
    // Equality at one index must be exact, while a later index may move to a
    // higher term or remain with the very same leader in the same term.
    // Another leader in that same term is a fork, not a descendant.
    match earlier.index.cmp(&later.index) {
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => earlier == later,
        std::cmp::Ordering::Less => match earlier.leader_id.term.cmp(&later.leader_id.term) {
            std::cmp::Ordering::Greater => false,
            std::cmp::Ordering::Equal => earlier.leader_id == later.leader_id,
            std::cmp::Ordering::Less => true,
        },
    }
}

/// A compacted terminal proof has no retained recovery marker to bind the
/// proof to the physical log. Both the durable purge floor and the selected
/// snapshot must therefore be descendants of the exact finalized LogId. An
/// index-only comparison would accept a lower-term or same-term/different-
/// leader branch that merely happens to have progressed farther numerically.
pub(super) fn require_compacted_terminal_log_lineage(
    finalize_log_id: &LogId<SessionConsensusNodeId>,
    purged: Option<&LogId<SessionConsensusNodeId>>,
    snapshot_log: &LogId<SessionConsensusNodeId>,
) -> Result<(), RecoveryError> {
    if !purged.is_some_and(|floor| full_log_id_not_after(finalize_log_id, floor))
        || !full_log_id_not_after(finalize_log_id, snapshot_log)
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(())
}

fn recovery_v2_request_id(plan: &RecoveryPlan) -> SessionConsensusRequestId {
    let mut request = [0_u8; 16];
    request.copy_from_slice(&plan.plan_digest.as_bytes()[..16]);
    SessionConsensusRequestId::from_bytes(request)
}

fn finalization_predecessor_from_plan(
    plan: &RecoveryPlan,
) -> Result<FinalizationPredecessorCapsule, RecoveryError> {
    let source = plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == plan.body.source_token)
        .ok_or(RecoveryError::StalePlan)?;
    let baseline = source
        .committed_log_id
        .ok_or(RecoveryError::BackupCorrupt)?;
    Ok(FinalizationPredecessorCapsule {
        recovery_epoch: source.recovery_epoch,
        last_plan_digest: source.last_plan_digest,
        watch_cursor_invalidation_floor: source.watch_cursor_invalidation_floor,
        baseline_log_id: baseline,
        application_sequence: source.application_sequence,
        machine_last_digest: source.machine_last_digest,
        machine_logical_time: source.machine_logical_time,
        watch_sequence: source.watch_sequence,
        authority_commitment: source.authority_commitment,
        recovery_v2_invariant_state_digest: source.recovery_v2_invariant_state_digest,
        bootstrap_membership_digest: source.predecessor_bootstrap_membership_digest,
        legacy_bootstrap_membership: None,
    })
}

fn recovery_v2_intent_from_predecessor(
    plan: &RecoveryPlan,
    predecessor: &FinalizationPredecessorCapsule,
) -> FinalizeOperatorRecoveryV2Intent {
    FinalizeOperatorRecoveryV2Intent {
        recovery_epoch: plan.body.next_recovery_epoch,
        plan_digest: plan.plan_digest.as_bytes(),
        fence_high_water: plan.body.fence_high_water,
        credential_high_water: plan.body.credential_high_water,
        application_sequence_high_water: plan.body.application_sequence_high_water,
        watch_cursor_invalidation_floor: plan.body.watch_cursor_invalidation_floor,
        predecessor_recovery_epoch: predecessor.recovery_epoch,
        predecessor_plan_digest: predecessor.last_plan_digest.as_bytes(),
        predecessor_watch_cursor_invalidation_floor: predecessor.watch_cursor_invalidation_floor,
        predecessor_baseline_log_id: predecessor.baseline_log_id,
        predecessor_application_sequence: predecessor.application_sequence,
        predecessor_last_digest: predecessor.machine_last_digest.as_bytes(),
        predecessor_logical_time: predecessor.machine_logical_time,
        predecessor_watch_sequence: predecessor.watch_sequence,
        predecessor_authority_commitment: predecessor.authority_commitment.as_bytes(),
        predecessor_recovery_v2_invariant_state_digest: predecessor
            .recovery_v2_invariant_state_digest
            .as_bytes(),
        predecessor_bootstrap_membership_digest: predecessor
            .bootstrap_membership_digest
            .map(RecoveryDigest::as_bytes),
    }
}

/// Construct the one exact V2 command which may finalize this plan.  Legacy
/// plans have no OpenRaft predecessor in their original evidence, so their
/// sealed bootstrap capsule replaces only that predecessor portion after it
/// has been MAC-journaled under the held fleet descriptors.
pub(super) fn recovery_v2_intent_from_plan(
    plan: &RecoveryPlan,
    legacy_predecessor: Option<&FinalizationPredecessorCapsule>,
) -> Result<FinalizeOperatorRecoveryV2Intent, RecoveryError> {
    let predecessor = legacy_predecessor
        .cloned()
        .map(Ok)
        .unwrap_or_else(|| finalization_predecessor_from_plan(plan))?;
    Ok(recovery_v2_intent_from_predecessor(plan, &predecessor))
}

/// The V2 application transaction may only transform logical lease state in
/// three ways: deactivate every lease and advance the two allocators to the
/// planned high-water plus one.  The complementary invariant-state digest
/// proves every other row stayed identical to the plan source.
fn recovery_v2_exact_lease_postconditions(
    conn: &Connection,
    fence_high_water: u64,
    credential_high_water: u64,
) -> Result<bool, RecoveryError> {
    let active_leases: i64 = conn
        .query_row("SELECT COUNT(*) FROM leases WHERE active <> 0", [], |row| {
            row.get(0)
        })
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    if active_leases != 0 {
        return Ok(false);
    }
    let expected_next_fence = fence_high_water
        .checked_add(1)
        .ok_or(RecoveryError::BackupCorrupt)?;
    let expected_next_credential = credential_high_water
        .checked_add(1)
        .ok_or(RecoveryError::BackupCorrupt)?;
    let next_fence: i64 = conn
        .query_row(
            "SELECT val FROM lease_globals WHERE key = 'next_fence'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    let next_credential: i64 = conn
        .query_row(
            "SELECT val FROM lease_globals WHERE key = 'next_credential_id'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    Ok(u64::try_from(next_fence).ok() == Some(expected_next_fence)
        && u64::try_from(next_credential).ok() == Some(expected_next_credential))
}

/// During finalization, an Active/PendingHandoff latch means no unrelated
/// application command is permitted to cross the recovery marker.  Scan the
/// exact baseline-to-head suffix rather than accepting a historical marker
/// with an arbitrary normal tail; that looser rule is only safe after a
/// durable Consumed terminal record has opened ordinary traffic.
#[allow(clippy::too_many_arguments)] // Exact independently authenticated recovery fields.
fn strict_recovery_v2_suffix(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    baseline: &LogId<SessionConsensusNodeId>,
    finalize_log_id: &LogId<SessionConsensusNodeId>,
    head: &LogId<SessionConsensusNodeId>,
    expected_request_id: SessionConsensusRequestId,
    expected_intent: &FinalizeOperatorRecoveryV2Intent,
    limits: RecoveryLimits,
) -> Result<crate::consensus::SessionConsensusCommand, RecoveryError> {
    if !full_log_id_not_after(baseline, finalize_log_id)
        || !full_log_id_not_after(finalize_log_id, head)
        || baseline == finalize_log_id
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    let start = baseline
        .index
        .checked_add(1)
        .ok_or(RecoveryError::BackupCorrupt)?;
    let end = head
        .index
        .checked_add(1)
        .ok_or(RecoveryError::BackupCorrupt)?;
    let count = end.checked_sub(start).ok_or(RecoveryError::BackupCorrupt)?;
    if count == 0 || count > limits.max_rows() {
        return Err(RecoveryError::BackupCorrupt);
    }
    let limit = usize::try_from(count).map_err(|_| RecoveryError::WorkLimitExceeded)?;
    let entries =
        consensus::read_log_range_for_recovery_sync(conn, identity, start, Some(end), Some(limit))
            .map_err(|_| RecoveryError::BackupCorrupt)?;
    if entries.len() != limit {
        return Err(RecoveryError::BackupCorrupt);
    }
    let mut expected_index = start;
    let mut final_command = None;
    for entry in entries {
        if entry.log_id.index != expected_index {
            return Err(RecoveryError::BackupCorrupt);
        }
        expected_index = expected_index
            .checked_add(1)
            .ok_or(RecoveryError::BackupCorrupt)?;
        match entry.payload {
            opc_consensus::engine::EntryPayload::Blank => {}
            opc_consensus::engine::EntryPayload::Normal(command)
                if entry.log_id == *finalize_log_id
                    && final_command.is_none()
                    && command.schema_version == SESSION_CONSENSUS_SCHEMA_VERSION
                    && command.identity == identity
                    && command.request_id == expected_request_id
                    && matches!(
                        &command.intent,
                        SessionMutationIntent::FinalizeOperatorRecoveryV2(payload)
                            if payload.as_ref() == expected_intent
                    ) =>
            {
                final_command = Some(command);
            }
            _ => return Err(RecoveryError::BackupCorrupt),
        }
    }
    final_command.ok_or(RecoveryError::BackupCorrupt)
}

/// Read the exact retained V2 marker after the durable terminal handoff has
/// opened traffic.  Unlike [`strict_recovery_v2_suffix`], this deliberately
/// does not constrain the later suffix: normal operations may already have
/// advanced the state machine, but they cannot rewrite this physical marker
/// or its request outcome.
fn retained_recovery_v2_marker(
    conn: &Connection,
    identity: SessionConsensusIdentity,
    finalize_log_id: &LogId<SessionConsensusNodeId>,
    expected_request_id: SessionConsensusRequestId,
    expected_intent: &FinalizeOperatorRecoveryV2Intent,
) -> Result<crate::consensus::SessionConsensusCommand, RecoveryError> {
    let end = finalize_log_id
        .index
        .checked_add(1)
        .ok_or(RecoveryError::BackupCorrupt)?;
    let entries = consensus::read_log_range_for_recovery_sync(
        conn,
        identity,
        finalize_log_id.index,
        Some(end),
        Some(1),
    )
    .map_err(|_| RecoveryError::BackupCorrupt)?;
    let [entry] = entries.as_slice() else {
        return Err(RecoveryError::BackupCorrupt);
    };
    if entry.log_id != *finalize_log_id {
        return Err(RecoveryError::BackupCorrupt);
    }
    let opc_consensus::engine::EntryPayload::Normal(command) = &entry.payload else {
        return Err(RecoveryError::BackupCorrupt);
    };
    if command.schema_version != SESSION_CONSENSUS_SCHEMA_VERSION
        || command.identity != identity
        || command.request_id != expected_request_id
        || !matches!(
            &command.intent,
            SessionMutationIntent::FinalizeOperatorRecoveryV2(payload)
                if payload.as_ref() == expected_intent
        )
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(command.clone())
}

/// An untouched voter may receive and durably commit the epoch log entry
/// before its state machine applies it.  Its physical Raft suffix can
/// therefore advance while every pre-commit recovery and application fact is
/// still exact.  Accept only that narrow state: the held descriptor, current
/// snapshot, and inspected authority/roster are checked by the caller, while
/// this predicate keeps every non-log fact pinned to the plan evidence.
fn verify_untargeted_installed_evidence(
    plan: &RecoveryPlan,
    planned: &RecoveryReplicaEvidence,
    evidence: &RecoveryReplicaEvidence,
    conn: &Connection,
    limits: RecoveryLimits,
) -> Result<UnappliedRecoveryFinalizePhase, RecoveryError> {
    let source = plan
        .body
        .evidence
        .iter()
        .find(|item| item.replica_token == plan.body.source_token)
        .ok_or(RecoveryError::StalePlan)?;
    if evidence.replica_token != planned.replica_token
        || evidence.backing_identity != planned.backing_identity
        || evidence.path_binding != planned.path_binding
        || evidence.file_identity != planned.file_identity
        || evidence.format != planned.format
        || evidence.cluster_digest != planned.cluster_digest
        || evidence.configuration_digest != planned.configuration_digest
        || evidence.configuration_epoch != planned.configuration_epoch
        || evidence.authority_profile != planned.authority_profile
        || evidence.authority_profile != plan.body.source_authority_profile
        || evidence.fixed_placement_policy != planned.fixed_placement_policy
        || evidence.fixed_placement_policy != plan.body.source_fixed_placement_policy
        || evidence.current_snapshot_identity != planned.current_snapshot_identity
        || evidence.recovery_epoch != planned.recovery_epoch
        || evidence.last_plan_digest != planned.last_plan_digest
        || evidence.pending_recovery_epoch.is_some()
        || evidence.pending_plan_digest.is_some()
        || evidence.watch_cursor_invalidation_floor != planned.watch_cursor_invalidation_floor
        || evidence.application_sequence != planned.application_sequence
        || evidence.watch_sequence != planned.watch_sequence
        || evidence.applied_log_id != planned.applied_log_id
        || evidence.fence_high_water != planned.fence_high_water
        || evidence.credential_high_water != planned.credential_high_water
        || evidence.logical_state_digest != planned.logical_state_digest
        || evidence.recovery_v2_invariant_state_digest != source.recovery_v2_invariant_state_digest
        || evidence.protected_roster_digest != planned.protected_roster_digest
        || evidence.protected_roster_digest != plan.body.source_protected_roster_digest
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    verify_exact_unapplied_recovery_finalize_suffix(plan, planned, evidence, conn, limits)
}

/// An epoch command may be committed in the Raft log before any voter applies
/// it.  This must not be collapsed into the installed predecessor: retrying a
/// proposal under the same deterministic request ID would allocate different
/// command bytes (notably a later logical time) and turn a recoverable apply
/// lag into a durable request conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnappliedRecoveryFinalizePhase {
    NoFinalize,
    ExactFinalizeInFlight,
}

/// Prove the only physical advancement an untouched voter may have while the
/// finalization command has committed but has not yet reached its state
/// machine. Planning requires its old head to be clean and equal to the
/// source committed branch; this scan therefore admits harmless Raft blanks
/// and exactly one authenticated recovery-finalize command, never an
/// arbitrary valid suffix from another campaign.
fn verify_exact_unapplied_recovery_finalize_suffix(
    plan: &RecoveryPlan,
    planned: &RecoveryReplicaEvidence,
    evidence: &RecoveryReplicaEvidence,
    conn: &Connection,
    limits: RecoveryLimits,
) -> Result<UnappliedRecoveryFinalizePhase, RecoveryError> {
    let planned_head = planned
        .local_head_log_id
        .ok_or(RecoveryError::BackupCorrupt)?;
    if planned.committed_log_id != Some(planned_head)
        || planned.applied_log_id != Some(planned_head)
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    let observed_head = evidence
        .local_head_log_id
        .ok_or(RecoveryError::BackupCorrupt)?;
    let observed_committed = evidence
        .committed_log_id
        .ok_or(RecoveryError::BackupCorrupt)?;
    if observed_head.index < planned_head.index
        || observed_committed != observed_head
        || evidence.applied_log_id != Some(planned_head)
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    let start = planned_head
        .index
        .checked_add(1)
        .ok_or(RecoveryError::BackupCorrupt)?;
    let end = observed_head
        .index
        .checked_add(1)
        .ok_or(RecoveryError::BackupCorrupt)?;
    let count = end.checked_sub(start).ok_or(RecoveryError::BackupCorrupt)?;
    if count > limits.max_rows() {
        return Err(RecoveryError::BackupCorrupt);
    }
    // Before the leader proposes the epoch entry an untouched agreeing voter
    // has no suffix at all.  It may also contain only inert Raft blanks; both
    // are still the exact installed predecessor rather than corruption.
    if count == 0 {
        return Ok(UnappliedRecoveryFinalizePhase::NoFinalize);
    }
    let limit = usize::try_from(count).map_err(|_| RecoveryError::WorkLimitExceeded)?;
    let entries = consensus::read_log_range_for_recovery_sync(
        conn,
        plan.body.identity,
        start,
        Some(end),
        Some(limit),
    )
    .map_err(|_| RecoveryError::BackupCorrupt)?;
    if entries.len() != limit {
        return Err(RecoveryError::BackupCorrupt);
    }
    let mut expected_index = start;
    let mut finalize_index = None;
    let mut expected_request_id = [0_u8; 16];
    expected_request_id.copy_from_slice(&plan.plan_digest.as_bytes()[..16]);
    for entry in entries {
        if entry.log_id.index != expected_index {
            return Err(RecoveryError::BackupCorrupt);
        }
        expected_index = expected_index
            .checked_add(1)
            .ok_or(RecoveryError::BackupCorrupt)?;
        match entry.payload {
            opc_consensus::engine::EntryPayload::Blank => {}
            opc_consensus::engine::EntryPayload::Normal(command)
                if finalize_index.is_none()
                    && command.schema_version == SESSION_CONSENSUS_SCHEMA_VERSION
                    && command.identity == plan.body.identity
                    && command.request_id.as_bytes() == &expected_request_id
                    && matches!(&command.intent,
                    SessionMutationIntent::FinalizeOperatorRecoveryV2(payload)
                    if recovery_v2_payload_matches_plan(
                        payload.as_ref(), plan, planned, planned_head,
                    )) =>
            {
                finalize_index = Some(entry.log_id.index);
            }
            _ => return Err(RecoveryError::BackupCorrupt),
        }
    }
    if finalize_index.is_some_and(|index| index > observed_committed.index) {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(match finalize_index {
        None => UnappliedRecoveryFinalizePhase::NoFinalize,
        Some(_) => UnappliedRecoveryFinalizePhase::ExactFinalizeInFlight,
    })
}

/// Legacy recovery uses a MACed bootstrap capsule rather than the immutable
/// legacy plan as its current-format Raft predecessor.  The exact physical
/// suffix rules remain identical: no advancement, blanks, or exactly the one
/// deterministic V2 marker waiting for state-machine application.
fn verify_legacy_exact_unapplied_recovery_finalize_suffix(
    plan: &RecoveryPlan,
    predecessor: &FinalizationPredecessorCapsule,
    evidence: &RecoveryReplicaEvidence,
    conn: &Connection,
    limits: RecoveryLimits,
) -> Result<UnappliedRecoveryFinalizePhase, RecoveryError> {
    let baseline = predecessor.baseline_log_id;
    let observed_head = evidence
        .local_head_log_id
        .ok_or(RecoveryError::BackupCorrupt)?;
    let observed_committed = evidence
        .committed_log_id
        .ok_or(RecoveryError::BackupCorrupt)?;
    if observed_head.index < baseline.index
        || observed_committed != observed_head
        || evidence.applied_log_id != Some(baseline)
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    let start = baseline
        .index
        .checked_add(1)
        .ok_or(RecoveryError::BackupCorrupt)?;
    let end = observed_head
        .index
        .checked_add(1)
        .ok_or(RecoveryError::BackupCorrupt)?;
    let count = end.checked_sub(start).ok_or(RecoveryError::BackupCorrupt)?;
    if count > limits.max_rows() {
        return Err(RecoveryError::BackupCorrupt);
    }
    if count == 0 {
        return Ok(UnappliedRecoveryFinalizePhase::NoFinalize);
    }
    let limit = usize::try_from(count).map_err(|_| RecoveryError::WorkLimitExceeded)?;
    let entries = consensus::read_log_range_for_recovery_sync(
        conn,
        plan.body.identity,
        start,
        Some(end),
        Some(limit),
    )
    .map_err(|_| RecoveryError::BackupCorrupt)?;
    if entries.len() != limit {
        return Err(RecoveryError::BackupCorrupt);
    }
    let expected_intent = recovery_v2_intent_from_predecessor(plan, predecessor);
    let expected_request_id = recovery_v2_request_id(plan);
    let mut expected_index = start;
    let mut saw_finalize = false;
    for entry in entries {
        if entry.log_id.index != expected_index {
            return Err(RecoveryError::BackupCorrupt);
        }
        expected_index = expected_index
            .checked_add(1)
            .ok_or(RecoveryError::BackupCorrupt)?;
        match entry.payload {
            opc_consensus::engine::EntryPayload::Blank => {}
            opc_consensus::engine::EntryPayload::Normal(command)
                if !saw_finalize
                    && command.schema_version == SESSION_CONSENSUS_SCHEMA_VERSION
                    && command.identity == plan.body.identity
                    && command.request_id == expected_request_id
                    && matches!(
                        &command.intent,
                        SessionMutationIntent::FinalizeOperatorRecoveryV2(payload)
                            if payload.as_ref() == &expected_intent
                    ) =>
            {
                saw_finalize = true;
            }
            _ => return Err(RecoveryError::BackupCorrupt),
        }
    }
    Ok(if saw_finalize {
        UnappliedRecoveryFinalizePhase::ExactFinalizeInFlight
    } else {
        UnappliedRecoveryFinalizePhase::NoFinalize
    })
}

fn recovery_v2_payload_matches_plan(
    payload: &FinalizeOperatorRecoveryV2Intent,
    plan: &RecoveryPlan,
    planned: &RecoveryReplicaEvidence,
    planned_head: LogId<SessionConsensusNodeId>,
) -> bool {
    payload.recovery_epoch == plan.body.next_recovery_epoch
        && payload.plan_digest == plan.plan_digest.as_bytes()
        && payload.fence_high_water == plan.body.fence_high_water
        && payload.credential_high_water == plan.body.credential_high_water
        && payload.application_sequence_high_water == plan.body.application_sequence_high_water
        && payload.watch_cursor_invalidation_floor == plan.body.watch_cursor_invalidation_floor
        && payload.predecessor_recovery_epoch == planned.recovery_epoch
        && payload.predecessor_plan_digest == planned.last_plan_digest.as_bytes()
        && payload.predecessor_watch_cursor_invalidation_floor
            == planned.watch_cursor_invalidation_floor
        && payload.predecessor_baseline_log_id == planned_head
        && payload.predecessor_application_sequence == planned.application_sequence
        && payload.predecessor_last_digest == planned.machine_last_digest.as_bytes()
        && payload.predecessor_logical_time == planned.machine_logical_time
        && payload.predecessor_watch_sequence == planned.watch_sequence
        && payload.predecessor_authority_commitment == planned.authority_commitment.as_bytes()
        && payload.predecessor_recovery_v2_invariant_state_digest
            == planned.recovery_v2_invariant_state_digest.as_bytes()
        && payload.predecessor_bootstrap_membership_digest
            == planned
                .predecessor_bootstrap_membership_digest
                .map(RecoveryDigest::as_bytes)
}

struct PreparedDatabaseInstall {
    temporary: PathBuf,
    parent: PathBuf,
    file: PinnedSnapshotFile,
}

fn prepare_staged_database(
    target: &RecoveryReplica,
    staged: &mut PinnedSnapshotFile,
    plan: &RecoveryPlan,
    resume_partial: bool,
) -> Result<PreparedDatabaseInstall, RecoveryError> {
    let (parent, temporary) = database_promotion_temporary_path(target, plan)?;
    if resume_partial {
        remove_regular_file_if_present(&temporary)?;
    } else {
        require_path_absent(&temporary)?;
    }
    let max = staged
        .file
        .metadata()
        .map_err(|_| RecoveryError::FileOperationFailed)?
        .len();
    let temporary_file = copy_file_bounded_from(&mut staged.file, &temporary, max)?;
    let conn = open_read_write_pinned(&temporary_file)?;
    ops::rotate_restore_scan_incarnation_sync(&conn)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    drop(conn);
    temporary_file
        .file
        .sync_all()
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    temporary_file
        .verify_path_identity(&temporary)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    // As with snapshot temporaries, the workflow may MAC this destination
    // before promotion. Durably publish the temporary dentry first.
    sync_directory(&parent)?;
    temporary_file
        .verify_path_identity(&temporary)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    Ok(PreparedDatabaseInstall {
        temporary,
        parent,
        file: temporary_file,
    })
}

fn promote_prepared_database(
    target: &RecoveryReplica,
    prepared: PreparedDatabaseInstall,
    destination: PromotionDestination<'_>,
) -> Result<PinnedSnapshotFile, RecoveryError> {
    let paths = canonical_replica_paths(target, false)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = paths.database.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        remove_regular_file_if_present(&sidecar)?;
    }
    promote_pinned_file(
        prepared.file,
        &prepared.temporary,
        &paths.database,
        &prepared.parent,
        destination,
    )
}

fn promote_prepared_database_from_workflow(
    key: &RecoveryIntegrityKey,
    target: &RecoveryReplica,
    plan: &RecoveryPlan,
    expected_identity: RecoveryDigest,
    disposition: PromotionDisposition,
) -> Result<PinnedSnapshotFile, RecoveryError> {
    let paths = canonical_replica_paths(target, false)?;
    let (parent, temporary) = database_promotion_temporary_path(target, plan)?;
    if let Some(file) = open_completed_promotion_from_workflow(
        key,
        &temporary,
        &paths.database,
        &parent,
        expected_identity,
        disposition,
    )? {
        return Ok(file);
    }
    match fs::symlink_metadata(&temporary) {
        Ok(_) => {
            let file =
                PinnedSnapshotFile::open(&temporary).map_err(|_| RecoveryError::BackupCorrupt)?;
            if pinned_file_identity(key, &file)? != expected_identity {
                return Err(RecoveryError::BackupCorrupt);
            }
            file.verify_path_identity(&temporary)
                .map_err(|_| RecoveryError::BackupCorrupt)?;
            let destination_pin =
                promotion_destination_from_workflow(key, &paths.database, disposition)?;
            promote_prepared_database(
                target,
                PreparedDatabaseInstall {
                    temporary,
                    parent: parent.clone(),
                    file,
                },
                promotion_destination_from_pin(destination_pin.as_ref()),
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // The process may have died after rename but before it could
            // replace the temporary commitment with the installed one.  The
            // destination is acceptable only if it is that same committed
            // inode, not merely identical SQLite bytes.
            let file = PinnedSnapshotFile::open(&paths.database)
                .map_err(|_| RecoveryError::BackupCorrupt)?;
            if pinned_file_identity(key, &file)? != expected_identity {
                return Err(RecoveryError::BackupCorrupt);
            }
            file.verify_path_identity(&paths.database)
                .map_err(|_| RecoveryError::BackupCorrupt)?;
            // A resumed DatabaseCopying workflow can observe the promoted
            // name after a crash before the original directory fsync. Do not
            // publish DatabaseInstalled until this exact dentry is durable.
            sync_directory(&parent).map_err(|_| RecoveryError::BackupCorrupt)?;
            file.verify_path_identity(&paths.database)
                .map_err(|_| RecoveryError::BackupCorrupt)?;
            Ok(file)
        }
        Err(_) => Err(RecoveryError::BackupCorrupt),
    }
}

fn require_database_install_temporary_absent(
    target: &RecoveryReplica,
    plan: &RecoveryPlan,
) -> Result<(), RecoveryError> {
    let (_, temporary) = database_promotion_temporary_path(target, plan)?;
    require_path_absent(&temporary)
}

/// Exchanges retain the displaced database at the temporary name.  The name
/// therefore has to be unique per target as well as per plan: several
/// replicas can share one parent directory, and their completed exchanges
/// must never block or be mistaken for one another on the same campaign.
fn database_promotion_temporary_path(
    target: &RecoveryReplica,
    plan: &RecoveryPlan,
) -> Result<(PathBuf, PathBuf), RecoveryError> {
    let paths = canonical_replica_paths(target, false)?;
    let parent = paths
        .database
        .parent()
        .ok_or(RecoveryError::InvalidRequest)?
        .to_path_buf();
    let target_component =
        RecoveryDigest::from_bytes(Sha256::digest(target.replica_id.as_str().as_bytes()).into())
            .to_hex();
    let temporary = parent.join(format!(
        ".opc-recovery-{}-{}.sqlite",
        &plan.plan_digest.to_hex()[..16],
        &target_component[..16],
    ));
    Ok((parent, temporary))
}

#[cfg(test)]
pub(super) fn database_promotion_temporary_path_for_test(
    target: &RecoveryReplica,
    plan: &RecoveryPlan,
) -> Result<PathBuf, RecoveryError> {
    database_promotion_temporary_path(target, plan).map(|(_, temporary)| temporary)
}

pub(super) fn resume_execution_state(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
) -> Result<RecoveryExecutionState, RecoveryError> {
    let directory = workflow_directory(backup_root, plan, false)?;
    read_workflow(key, plan, &directory)?
        .map(|record| record.state)
        .ok_or(RecoveryError::StalePlan)
}

#[cfg(test)]
pub(super) fn promotion_cleanup_journals_are_empty_for_test(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
) -> Result<bool, RecoveryError> {
    let directory = workflow_directory(backup_root, plan, false)?;
    let record = read_workflow(key, plan, &directory)?.ok_or(RecoveryError::StalePlan)?;
    Ok(record.target_temporary_database_identities.is_empty()
        && record.target_temporary_database_destinations.is_empty()
        && record.target_temporary_snapshot_identities.is_empty()
        && record.target_temporary_snapshot_destinations.is_empty())
}

pub(super) fn resume_audit_state(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
) -> Result<Option<RecoveryExecutionState>, RecoveryError> {
    let directory = workflow_directory(backup_root, plan, false)?;
    let record = read_workflow(key, plan, &directory)?.ok_or(RecoveryError::StalePlan)?;
    Ok(record.audit_resume_state)
}

pub(super) fn record_epoch_committed(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
) -> Result<(), RecoveryError> {
    transition_workflow(
        key,
        plan,
        backup_root,
        RecoveryExecutionState::EpochCommitted,
    )
}

/// Persist the one common terminal proof and the Rejoined transition in the
/// same authenticated workflow replacement.  This happens while every
/// sidecar is still Active, before any terminal publication can make a
/// historical marker eligible for compaction.
pub(super) fn record_rejoined_with_terminal_proof(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
    pins: &mut FinalizationPins<'_>,
    limits: RecoveryLimits,
) -> Result<(), RecoveryError> {
    let directory = workflow_directory(backup_root, plan, false)?;
    let mut record = read_workflow(key, plan, &directory)?.ok_or(RecoveryError::StalePlan)?;
    if record.state != RecoveryExecutionState::EpochCommitted
        || !record.rejoin_proven
        || record.terminal_proof.is_some()
    {
        return Err(RecoveryError::StalePlan);
    }
    let predecessor = pins
        .legacy_predecessor
        .clone()
        .map(Ok)
        .unwrap_or_else(|| finalization_predecessor_from_plan(plan))?;
    let mut common = None;
    for latch in &mut pins.latches {
        if finalization_latch_sidecar_phase(plan, latch)?
            != consensus::OperatorRecoveryLatchPhase::Active
        {
            return Err(RecoveryError::BackupCorrupt);
        }
        if pinned_file_identity(key, &latch.database)? != latch.database_identity {
            return Err(RecoveryError::BackupCorrupt);
        }
        latch
            .database
            .verify_path_identity(&latch.database_path)
            .map_err(|_| RecoveryError::BackupCorrupt)?;
        let (_evidence, candidate) = inspect_replica_from_pinned_with(
            InspectionInput {
                key,
                replica: latch.replica,
                identity: plan.body.identity,
                expected_members: &plan.body.expected_members,
                limits,
            },
            canonical_replica_paths(latch.replica, false)?,
            &latch.database,
            latch.snapshot.as_mut(),
            |evidence, conn| {
                verify_exact_finalized_recovery_v2(
                    plan,
                    evidence,
                    conn,
                    limits,
                    FinalizedRecoveryV2ProofPhase::PreTerminalStrict,
                    Some(&predecessor),
                    None,
                )?;
                capture_terminal_proof_candidate(plan, evidence, conn, limits, &predecessor)
            },
        )?;
        match &common {
            Some(expected) if expected != &candidate => return Err(RecoveryError::BackupCorrupt),
            Some(_) => {}
            None => common = Some(candidate),
        }
        if finalization_latch_sidecar_phase(plan, latch)?
            != consensus::OperatorRecoveryLatchPhase::Active
        {
            return Err(RecoveryError::BackupCorrupt);
        }
    }
    let proof = common.ok_or(RecoveryError::BackupCorrupt)?;
    transition_record_state(&mut record, RecoveryExecutionState::Rejoined)?;
    record.terminal_proof = Some(proof.clone());
    write_workflow(key, &directory, &record)?;
    pins.terminal_proof = Some(proof);
    Ok(())
}

fn capture_terminal_proof_candidate(
    plan: &RecoveryPlan,
    evidence: &RecoveryReplicaEvidence,
    conn: &Connection,
    limits: RecoveryLimits,
    predecessor: &FinalizationPredecessorCapsule,
) -> Result<RecoveryTerminalProofV1, RecoveryError> {
    let finalize_log_id = evidence
        .finalize_log_id
        .ok_or(RecoveryError::BackupCorrupt)?;
    let head = evidence
        .local_head_log_id
        .ok_or(RecoveryError::BackupCorrupt)?;
    let request_id = recovery_v2_request_id(plan);
    let intent = recovery_v2_intent_from_predecessor(plan, predecessor);
    let command = strict_recovery_v2_suffix(
        conn,
        plan.body.identity,
        &predecessor.baseline_log_id,
        &finalize_log_id,
        &head,
        request_id,
        &intent,
        limits,
    )?;
    let recovery_application_sequence = plan
        .body
        .application_sequence_high_water
        .checked_add(1)
        .ok_or(RecoveryError::BackupCorrupt)?;
    let effective_logical_time = predecessor
        .machine_logical_time
        .map_or(command.logical_time, |last| last.max(command.logical_time));
    let applied_digest = command
        .calculate_applied_digest(
            recovery_application_sequence,
            SessionConsensusEntryDigest::from_bytes(predecessor.machine_last_digest.as_bytes()),
            effective_logical_time,
        )
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    let intent_payload_digest = RecoveryDigest::from_bytes(
        consensus::operator_recovery_v2_payload_digest_sync(
            plan.body.identity,
            &SessionMutationIntent::FinalizeOperatorRecoveryV2(Box::new(intent)),
        )
        .map_err(|_| RecoveryError::BackupCorrupt)?,
    );
    let certificate_outcome = verified_finalize_certificate_outcome(
        conn,
        plan.body.identity,
        &finalize_log_id,
        request_id,
        intent_payload_digest,
        command.logical_time,
        recovery_application_sequence,
        applied_digest,
        effective_logical_time,
    )?;
    let outcome = consensus::exact_operator_recovery_v2_outcome_sync(
        conn,
        plan.body.identity,
        request_id,
        intent_payload_digest.as_bytes(),
        &finalize_log_id,
        recovery_application_sequence,
        applied_digest,
        effective_logical_time,
    )
    .map_err(|_| RecoveryError::BackupCorrupt)?
    .ok_or(RecoveryError::BackupCorrupt)?;
    if terminal_outcome_commitment(&outcome)? != terminal_outcome_commitment(&certificate_outcome)?
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(RecoveryTerminalProofV1 {
        proof_revision: RECOVERY_TERMINAL_PROOF_REVISION,
        proof_domain: RECOVERY_TERMINAL_PROOF_DOMAIN.to_owned(),
        identity: plan.body.identity,
        recovery_epoch: plan.body.next_recovery_epoch,
        plan_digest: plan.plan_digest,
        predecessor: predecessor.clone(),
        finalize_log_id,
        command_schema_version: command.schema_version,
        request_id,
        original_command_logical_time: command.logical_time,
        intent_payload_digest,
        recovery_application_sequence,
        effective_logical_time,
        applied_digest: RecoveryDigest::from_bytes(*applied_digest.as_bytes()),
        outcome_commitment: terminal_outcome_commitment(&outcome)?,
    })
}

pub(super) fn record_rejoin_proven(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
) -> Result<(), RecoveryError> {
    let directory = workflow_directory(backup_root, plan, false)?;
    let mut record = read_workflow(key, plan, &directory)?.ok_or(RecoveryError::StalePlan)?;
    if !matches!(
        record.state,
        RecoveryExecutionState::EpochCommitted | RecoveryExecutionState::AuditPending
    ) {
        return Err(RecoveryError::StalePlan);
    }
    record.rejoin_proven = true;
    write_workflow(key, &directory, &record)
}

pub(super) fn record_audit_pending(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
) -> Result<(), RecoveryError> {
    transition_workflow(key, plan, backup_root, RecoveryExecutionState::AuditPending)
}

pub(super) fn transition_after_audit(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
    resume: RecoveryExecutionState,
) -> Result<(), RecoveryError> {
    transition_workflow(key, plan, backup_root, resume)
}

fn transition_workflow(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
    state: RecoveryExecutionState,
) -> Result<(), RecoveryError> {
    let directory = workflow_directory(backup_root, plan, false)?;
    let mut record = read_workflow(key, plan, &directory)?.ok_or(RecoveryError::StalePlan)?;
    transition_record_state(&mut record, state)?;
    write_workflow(key, &directory, &record)
}

/// Build the minimum fully bound snapshot-bearing post-execute workflow used
/// by the finalization failpoint test. The production path writes these fields
/// while holding copied destination descriptors; this singleton fixture pins
/// the same real database and selected snapshot while separately installing
/// the exact pending intent because no live leader exists after offline
/// replacement. It therefore exercises finalization and the production
/// terminal handoff without hand-assembling a sidecar.
#[cfg(test)]
pub(super) fn prepare_test_workflow_with_current_snapshot(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
    state: RecoveryExecutionState,
    target: &RecoveryReplica,
) -> Result<(), RecoveryError> {
    prepare_test_workflow_inner(key, plan, backup_root, state, target)
}

#[cfg(test)]
fn prepare_test_workflow_inner(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
    state: RecoveryExecutionState,
    target: &RecoveryReplica,
) -> Result<(), RecoveryError> {
    let directory = workflow_directory(backup_root, plan, true)?;
    let target_token = super::replica_token(key, &target.replica_id)?;
    if plan.body.target_tokens.as_slice() != [target_token] {
        return Err(RecoveryError::InvalidRequest);
    }
    let target_paths = canonical_replica_paths(target, false)?;
    let mut database = PinnedSnapshotFile::open(&target_paths.database)
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    let database_identity = pinned_file_identity(key, &database)?;
    let database_digest = digest_pinned_file(
        &mut database,
        RecoveryLimits::default().max_database_bytes(),
    )?
    .0;
    database
        .verify_path_identity(&target_paths.database)
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    let mut snapshot = current_snapshot_reference_from_pinned(
        &database,
        plan.body.identity,
        &target_paths.snapshots,
        RecoveryLimits::default(),
        None,
    )?
    .ok_or(RecoveryError::InvalidRequest)?;
    let digest = digest_pinned_file(
        &mut snapshot.file,
        RecoveryLimits::default().max_snapshot_bytes(),
    )?
    .0;
    let identity = pinned_file_identity(key, &snapshot.file)?;
    let path = target_paths.snapshots.join(&snapshot.file_name);
    snapshot.file.verify_path_identity(&path)?;
    let snapshot = (snapshot.file_name, digest, identity);
    let target_key = target_token.to_hex();
    let target_installed = matches!(
        state,
        RecoveryExecutionState::AwaitingEpochCommit
            | RecoveryExecutionState::EpochCommitted
            | RecoveryExecutionState::Rejoined
            | RecoveryExecutionState::AuditPending
    );
    ensure_fleet_latches(key, plan, std::slice::from_ref(target))?;
    write_workflow(
        key,
        &directory,
        &WorkflowRecord {
            version: WORKFLOW_VERSION,
            plan_digest: plan.plan_digest,
            limits: WorkflowLimits::from_recovery(RecoveryLimits::default()),
            source_branch_digest: plan.body.source_branch_digest,
            source_authority_profile: plan.body.source_authority_profile,
            source_fixed_placement_policy: plan.body.source_fixed_placement_policy,
            source_protected_roster_digest: plan.body.source_protected_roster_digest,
            legacy_finalization_predecessor: None,
            terminal_proof: None,
            target_tokens: plan.body.target_tokens.clone(),
            state,
            audit_resume_state: (state == RecoveryExecutionState::AuditPending)
                .then_some(RecoveryExecutionState::AwaitingEpochCommit),
            rejoin_proven: state == RecoveryExecutionState::Rejoined,
            checkpoint_database_digest: None,
            checkpoint_database_identity: None,
            checkpoint_snapshot_digest: None,
            checkpoint_snapshot_identity: None,
            staged_database_digest: Some(database_digest),
            staged_database_identity: Some(database_identity),
            staged_snapshot_digest: Some(snapshot.1),
            staged_snapshot_identity: Some(snapshot.2),
            source_snapshot_name: None,
            staged_snapshot_name: Some(snapshot.0.clone()),
            checkpoint_progress: FileProgress::Pending,
            staged_progress: FileProgress::Verified,
            target_backups: BTreeMap::from([(target_key.clone(), FileProgress::Pending)]),
            target_installs: BTreeMap::from([(
                target_key.clone(),
                if target_installed {
                    TargetInstallState::DatabaseInstalled
                } else {
                    TargetInstallState::Pending
                },
            )]),
            target_database_identities: target_installed
                .then_some((target_key.clone(), database_identity))
                .into_iter()
                .collect(),
            target_temporary_database_identities: BTreeMap::new(),
            target_temporary_database_destinations: BTreeMap::new(),
            target_snapshot_identities: target_installed
                .then_some((target_key, Some(snapshot.2)))
                .into_iter()
                .collect(),
            target_temporary_snapshot_identities: BTreeMap::new(),
            target_temporary_snapshot_destinations: BTreeMap::new(),
        },
    )
}

fn transition_record_state(
    record: &mut WorkflowRecord,
    next: RecoveryExecutionState,
) -> Result<(), RecoveryError> {
    if record.state == next {
        return Ok(());
    }
    if record.state == RecoveryExecutionState::AuditPending {
        if record.audit_resume_state != Some(next) {
            return Err(RecoveryError::StalePlan);
        }
        record.state = next;
        record.audit_resume_state = None;
        return Ok(());
    }
    if next == RecoveryExecutionState::AuditPending {
        record.audit_resume_state = Some(record.state);
        record.state = next;
        return Ok(());
    }
    let allowed = matches!(
        (record.state, next),
        (
            RecoveryExecutionState::Planned,
            RecoveryExecutionState::BackupVerified
        ) | (
            RecoveryExecutionState::BackupVerified,
            RecoveryExecutionState::AwaitingEpochCommit
        ) | (
            RecoveryExecutionState::AwaitingEpochCommit,
            RecoveryExecutionState::EpochCommitted
        ) | (
            RecoveryExecutionState::EpochCommitted,
            RecoveryExecutionState::Rejoined
        )
    );
    if !allowed {
        return Err(RecoveryError::StalePlan);
    }
    if next == RecoveryExecutionState::Rejoined && !record.rejoin_proven {
        return Err(RecoveryError::StalePlan);
    }
    record.state = next;
    Ok(())
}

fn validate_workflow_shape(
    plan: &RecoveryPlan,
    record: &WorkflowRecord,
) -> Result<(), RecoveryError> {
    let expected_targets = plan
        .body
        .target_tokens
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let observed_targets = record
        .target_installs
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let observed_backups = record
        .target_backups
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let observed_database_identities = record
        .target_database_identities
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let observed_temporary_database_identities = record
        .target_temporary_database_identities
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let observed_temporary_database_destinations = record
        .target_temporary_database_destinations
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let observed_snapshot_identities = record
        .target_snapshot_identities
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let observed_temporary_snapshot_identities = record
        .target_temporary_snapshot_identities
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let observed_temporary_snapshot_destinations = record
        .target_temporary_snapshot_destinations
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let snapshot_installed_targets = record
        .target_installs
        .iter()
        .filter_map(|(token, state)| {
            (*state >= TargetInstallState::SnapshotInstalled).then_some(token.clone())
        })
        .collect::<BTreeSet<_>>();
    let snapshot_promoting_targets = record
        .target_installs
        .iter()
        .filter_map(|(token, state)| {
            (*state == TargetInstallState::SnapshotPromoting).then_some(token.clone())
        })
        .collect::<BTreeSet<_>>();
    let installed_targets = record
        .target_installs
        .iter()
        .filter_map(|(token, state)| {
            (*state == TargetInstallState::DatabaseInstalled).then_some(token.clone())
        })
        .collect::<BTreeSet<_>>();
    let database_copying_targets = record
        .target_installs
        .iter()
        .filter_map(|(token, state)| {
            (*state == TargetInstallState::DatabaseCopying).then_some(token.clone())
        })
        .collect::<BTreeSet<_>>();
    if expected_targets != observed_targets
        || expected_targets != observed_backups
        || record.checkpoint_database_digest.is_some()
            && observed_database_identities != installed_targets
        || !observed_temporary_database_identities.is_subset(&database_copying_targets)
        || observed_temporary_database_destinations != observed_temporary_database_identities
        || record.checkpoint_database_digest.is_some()
            && observed_snapshot_identities != snapshot_installed_targets
        || observed_temporary_snapshot_identities != snapshot_promoting_targets
        || observed_temporary_snapshot_destinations != observed_temporary_snapshot_identities
        || (record.state == RecoveryExecutionState::AuditPending)
            != record.audit_resume_state.is_some()
        || record
            .audit_resume_state
            .is_some_and(|state| state == RecoveryExecutionState::AuditPending)
        || record.rejoin_proven
            && !matches!(
                record.state,
                RecoveryExecutionState::EpochCommitted
                    | RecoveryExecutionState::Rejoined
                    | RecoveryExecutionState::AuditPending
            )
        || (record.state == RecoveryExecutionState::Rejoined) != record.terminal_proof.is_some()
        || record.terminal_proof.as_ref().is_some_and(|proof| {
            proof.proof_revision != RECOVERY_TERMINAL_PROOF_REVISION
                || proof.proof_domain != RECOVERY_TERMINAL_PROOF_DOMAIN
                || proof.identity != plan.body.identity
                || proof.recovery_epoch != plan.body.next_recovery_epoch
                || proof.plan_digest != plan.plan_digest
        })
        || record.checkpoint_database_digest.is_some()
            != (record.checkpoint_progress == FileProgress::Verified)
        || record.checkpoint_database_digest.is_some()
            != record.checkpoint_database_identity.is_some()
        || record.checkpoint_snapshot_digest.is_some()
            != record.checkpoint_snapshot_identity.is_some()
        || record.source_snapshot_name.is_some() != record.checkpoint_snapshot_digest.is_some()
        || record.checkpoint_snapshot_digest.is_some()
            && record.checkpoint_database_digest.is_none()
        || record.staged_database_digest.is_some()
            != (record.staged_progress == FileProgress::Verified)
        || record.staged_database_digest.is_some() != record.staged_database_identity.is_some()
        || record.staged_snapshot_digest.is_some() != record.staged_snapshot_identity.is_some()
        || record.staged_snapshot_name.is_some() != record.staged_snapshot_digest.is_some()
        || record.staged_snapshot_digest.is_some()
            && record.staged_progress != FileProgress::Verified
        || matches!(
            record.state,
            RecoveryExecutionState::AwaitingEpochCommit
                | RecoveryExecutionState::EpochCommitted
                | RecoveryExecutionState::Rejoined
                | RecoveryExecutionState::AuditPending
        ) && record
            .target_installs
            .values()
            .any(|state| *state != TargetInstallState::DatabaseInstalled)
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(())
}

fn workflow_directory(
    backup_root: &Path,
    plan: &RecoveryPlan,
    create: bool,
) -> Result<PathBuf, RecoveryError> {
    validate_path_text(backup_root)?;
    if create {
        create_private_directory(backup_root)?;
    } else {
        validate_private_directory(backup_root)?;
    }
    let root = fs::canonicalize(backup_root).map_err(|_| RecoveryError::FileOperationFailed)?;
    validate_private_directory(&root)?;
    let directory = root.join(format!("recovery-{}", plan.plan_digest));
    if create {
        create_private_directory(&directory)?;
    } else {
        validate_private_directory(&directory)?;
    }
    Ok(directory)
}

fn create_private_directory(path: &Path) -> Result<(), RecoveryError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder
                .create(path)
                .map_err(|_| RecoveryError::FileOperationFailed)?;
            set_private_directory_permissions(path)?;
            validate_private_directory(path)
        }
        Err(_) => Err(RecoveryError::FileOperationFailed),
    }
}

fn validate_private_directory(path: &Path) -> Result<(), RecoveryError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RecoveryError::FileOperationFailed)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(RecoveryError::FileOperationFailed);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(RecoveryError::FileOperationFailed);
        }
    }
    Ok(())
}

fn set_private_directory_permissions(path: &Path) -> Result<(), RecoveryError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| RecoveryError::FileOperationFailed)?;
    }
    Ok(())
}

fn validate_private_file(path: &Path) -> Result<fs::Metadata, RecoveryError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RecoveryError::BackupCorrupt)?;
    validate_private_file_metadata(&metadata)?;
    Ok(metadata)
}

fn validate_private_file_metadata(metadata: &fs::Metadata) -> Result<(), RecoveryError> {
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(RecoveryError::BackupCorrupt);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(RecoveryError::BackupCorrupt);
        }
    }
    Ok(())
}

fn private_create_new(path: &Path) -> Result<File, RecoveryError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| RecoveryError::FileOperationFailed)?;
    }
    Ok(file)
}

fn read_workflow(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    directory: &Path,
) -> Result<Option<WorkflowRecord>, RecoveryError> {
    let path = directory.join("workflow.json");
    if !path.exists() {
        return Ok(None);
    }
    let sealed: SealedWorkflowRecord = read_bounded_json(&path, 64 * 1024)?;
    let encoded = serde_json::to_vec(&sealed.record).map_err(|_| RecoveryError::BackupCorrupt)?;
    verify_mac(key, WORKFLOW_MAC_DOMAIN, &[&encoded], sealed.mac)?;
    if sealed.record.version != WORKFLOW_VERSION
        || sealed.record.plan_digest != plan.plan_digest
        || sealed.record.source_branch_digest != plan.body.source_branch_digest
        || sealed.record.source_authority_profile != plan.body.source_authority_profile
        || sealed.record.source_fixed_placement_policy != plan.body.source_fixed_placement_policy
        || sealed.record.source_protected_roster_digest != plan.body.source_protected_roster_digest
        || sealed.record.target_tokens != plan.body.target_tokens
    {
        return Err(RecoveryError::StalePlan);
    }
    validate_workflow_shape(plan, &sealed.record)?;
    Ok(Some(sealed.record))
}

/// Recover the caller-selected execution bounds from the authenticated
/// workflow.  Finalization has no independent limits parameter, so accepting
/// default limits here would widen a deliberately constrained execute after a
/// restart.
pub(super) fn workflow_limits(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    backup_root: &Path,
) -> Result<RecoveryLimits, RecoveryError> {
    let directory = workflow_directory(backup_root, plan, false)?;
    read_workflow(key, plan, &directory)?
        .ok_or(RecoveryError::StalePlan)?
        .limits
        .recovery_limits()
}

fn write_workflow(
    key: &RecoveryIntegrityKey,
    directory: &Path,
    record: &WorkflowRecord,
) -> Result<(), RecoveryError> {
    let encoded = serde_json::to_vec(record).map_err(|_| RecoveryError::FileOperationFailed)?;
    let mac = RecoveryDigest::from_bytes(plan_mac(key, WORKFLOW_MAC_DOMAIN, &[&encoded])?);
    atomic_write_json(
        &directory.join("workflow.json"),
        &SealedWorkflowRecord {
            record: record.clone(),
            mac,
        },
    )?;
    sync_directory(directory)
}

struct SnapshotReference {
    file_name: String,
    file: PinnedSnapshotFile,
    fixed_immutable: bool,
}

/// Authenticate the currently selected snapshot inode while inspecting a
/// replica.  The plan carries this separate inode commitment so the later
/// checkpoint copy cannot accept a byte-identical replacement merely because
/// its envelope checksum still agrees with SQLite metadata.
fn current_snapshot_identity(
    key: &RecoveryIntegrityKey,
    conn: &Connection,
    identity: SessionConsensusIdentity,
    snapshot_dir: &Path,
    fixed_immutable: bool,
    limits: RecoveryLimits,
    pinned_snapshot: Option<&mut PinnedSnapshotFile>,
) -> Result<Option<RecoveryDigest>, RecoveryError> {
    let snapshot = consensus::read_current_snapshot_sync(conn, identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let Some((_, file_name, checksum, length)) = snapshot else {
        return Ok(None);
    };
    validate_snapshot_name(&file_name)?;
    let path = snapshot_dir.join(file_name);
    match pinned_snapshot {
        Some(file) => current_snapshot_identity_from_pinned(
            key,
            file,
            &path,
            fixed_immutable,
            checksum,
            length,
            limits,
        ),
        None => {
            let mut file = PinnedSnapshotFile::open(&path)?;
            current_snapshot_identity_from_pinned(
                key,
                &mut file,
                &path,
                fixed_immutable,
                checksum,
                length,
                limits,
            )
        }
    }
}

fn current_snapshot_identity_from_pinned(
    key: &RecoveryIntegrityKey,
    file: &mut PinnedSnapshotFile,
    path: &Path,
    fixed_immutable: bool,
    checksum: [u8; 32],
    length: u64,
    limits: RecoveryLimits,
) -> Result<Option<RecoveryDigest>, RecoveryError> {
    // A supplied descriptor must name the snapshot selected by the exact
    // pinned database.  This path resolution is only an equality assertion,
    // never an authority-bearing open.
    file.verify_path_identity(path)?;
    if fixed_immutable {
        measure_fixed_snapshot_file(file)?;
    }
    let observed = verify_pinned_snapshot_file(file, limits.max_snapshot_bytes(), None)?;
    if observed != (checksum, length) {
        return Err(RecoveryError::CorruptReplica);
    }
    let snapshot_identity = pinned_file_identity(key, file)?;
    file.verify_path_identity(path)?;
    Ok(Some(snapshot_identity))
}

/// A regular snapshot file held open across every operation that authenticates
/// or moves it.  A pathname is only a lookup; this descriptor is the object
/// whose fs-verity state, envelope and inode identity are trusted.
struct PinnedSnapshotFile {
    file: File,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

/// Opaque target-descriptor set retained by `finalize_inner` across consensus
/// commit, rejoin and audit.  The workflow MAC commits the expected inodes;
/// this value keeps those exact inodes alive instead of repeatedly trusting a
/// freshly resolved target pathname at each finalization boundary.
pub(super) struct FinalizationPins<'a> {
    targets: Vec<FinalizationTargetPin<'a>>,
    latches: Vec<FleetLatchPin<'a>>,
    legacy_predecessor: Option<FinalizationPredecessorCapsule>,
    terminal_proof: Option<RecoveryTerminalProofV1>,
}

/// Exact state of the fleet while an operator-recovery epoch is propagating.
/// This is deliberately narrower than a boolean: a follower may be either
/// exactly installed or exactly finalized after the leader has committed, but
/// no other semantic state is a recoverable transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FinalizationTransitionState {
    AllInstalled,
    /// The exact V2 command is durably committed but has not reached every
    /// state machine.  It is a retryable availability state, never a reason
    /// to issue a second command under the same deterministic request ID.
    ExactFinalizeInFlight,
    AllFinalized,
    MixedConverging,
}

struct FinalizationTargetPin<'a> {
    replica: &'a RecoveryReplica,
    database_path: PathBuf,
    database: PinnedSnapshotFile,
    database_identity: RecoveryDigest,
    snapshot_path: Option<PathBuf>,
    snapshot: Option<PinnedSnapshotFile>,
    snapshot_identity: Option<RecoveryDigest>,
    snapshot_digest: Option<RecoveryDigest>,
    fixed_immutable: bool,
}

struct FleetLatchPin<'a> {
    replica: &'a RecoveryReplica,
    replica_token: RecoveryDigest,
    database_path: PathBuf,
    database: PinnedSnapshotFile,
    database_identity: RecoveryDigest,
    snapshot_path: Option<PathBuf>,
    snapshot: Option<PinnedSnapshotFile>,
    snapshot_identity: Option<RecoveryDigest>,
    snapshot_digest: Option<RecoveryDigest>,
    fixed_immutable: bool,
    target_install: bool,
}

/// Snapshot each raw sidecar phase through the held descriptors before any
/// installed/finalized semantic verifier runs.  The caller must repeat this
/// exact raw observation after all semantic work: Active and PendingHandoff
/// are both strict before release, but they are not interchangeable states.
fn finalization_fleet_latch_sidecar_phases(
    plan: &RecoveryPlan,
    latches: &[FleetLatchPin<'_>],
) -> Result<BTreeMap<RecoveryDigest, consensus::OperatorRecoveryLatchPhase>, RecoveryError> {
    let mut phases = BTreeMap::new();
    for latch in latches {
        if phases
            .insert(
                latch.replica_token,
                finalization_latch_sidecar_phase(plan, latch)?,
            )
            .is_some()
        {
            return Err(RecoveryError::BackupCorrupt);
        }
    }
    if phases.len() != latches.len() || phases.is_empty() {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(phases)
}

/// Derive the one proof regime for the entire fleet.  A terminal proof alone
/// does not release history: ordinary traffic is admissible only after at
/// least one exact sidecar has been consumed by a live core.  Until then,
/// every Active or PendingHandoff voter remains strict.
fn finalization_fleet_proof_phase(
    sidecar_phases: &BTreeMap<RecoveryDigest, consensus::OperatorRecoveryLatchPhase>,
    terminal_proof: Option<&RecoveryTerminalProofV1>,
) -> Result<FinalizedRecoveryV2ProofPhase, RecoveryError> {
    let saw_consumed = sidecar_phases
        .values()
        .any(|phase| matches!(phase, consensus::OperatorRecoveryLatchPhase::Consumed));
    if !saw_consumed {
        if sidecar_phases.values().all(|phase| {
            matches!(
                phase,
                consensus::OperatorRecoveryLatchPhase::Active
                    | consensus::OperatorRecoveryLatchPhase::PendingHandoff
            )
        }) {
            return Ok(FinalizedRecoveryV2ProofPhase::PreTerminalStrict);
        }
        return Err(RecoveryError::BackupCorrupt);
    }

    if terminal_proof.is_none()
        || sidecar_phases
            .values()
            .any(|phase| matches!(phase, consensus::OperatorRecoveryLatchPhase::Active))
        || !sidecar_phases.values().all(|phase| {
            matches!(
                phase,
                consensus::OperatorRecoveryLatchPhase::PendingHandoff
                    | consensus::OperatorRecoveryLatchPhase::Consumed
            )
        })
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(FinalizedRecoveryV2ProofPhase::PostTerminalHistorical)
}

fn finalization_latch_sidecar_phase(
    plan: &RecoveryPlan,
    latch: &FleetLatchPin<'_>,
) -> Result<consensus::OperatorRecoveryLatchPhase, RecoveryError> {
    let snapshot = match (
        latch.snapshot_path.as_deref(),
        latch.snapshot.as_ref(),
        latch.snapshot_digest,
    ) {
        (Some(path), Some(file), Some(_)) => Some(
            consensus::operator_recovery_terminal_snapshot(path, &file.file, latch.fixed_immutable)
                .map_err(|_| RecoveryError::BackupCorrupt)?,
        ),
        (None, None, None) => None,
        _ => return Err(RecoveryError::BackupCorrupt),
    };
    consensus::operator_recovery_latch_phase_sync(
        &latch.database_path,
        expected_latch(plan, false),
        &latch.database.file,
        Some(snapshot.as_ref()),
    )
    .map_err(|_| RecoveryError::BackupCorrupt)
}

/// After Rejoined's authenticated common proof exists, a locally consumed
/// replica may have legitimately published a newer selected snapshot and
/// purged the historical marker.  Re-pin that replica's current snapshot
/// rather than comparing it to the pre-release workflow image; Active and
/// Pending replicas never receive this exception.
fn workflow_allows_historical_consumed_latch(
    plan: &RecoveryPlan,
    workflow: &WorkflowRecord,
    database_path: &Path,
    database_file: &File,
) -> Result<bool, RecoveryError> {
    if workflow.state != RecoveryExecutionState::Rejoined || workflow.terminal_proof.is_none() {
        return Ok(false);
    }
    Ok(matches!(
        consensus::operator_recovery_latch_phase_sync(
            database_path,
            expected_latch(plan, false),
            database_file,
            None,
        )
        .map_err(|_| RecoveryError::BackupCorrupt)?,
        consensus::OperatorRecoveryLatchPhase::Consumed
    ))
}

/// Pin and authenticate every installed target before finalization.  A
/// completed execute may have happened in another process, so this is the
/// first finalization operation and must compare both target inode MACs with
/// the workflow before any irreversible consensus operation begins.
pub(super) fn acquire_finalization_pins<'a>(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    replicas: &'a [RecoveryReplica],
    backup_root: &Path,
    limits: RecoveryLimits,
) -> Result<FinalizationPins<'a>, RecoveryError> {
    validate_fleet_replica_set(key, plan, replicas)?;
    let directory = workflow_directory(backup_root, plan, false)?;
    let workflow = read_workflow(key, plan, &directory)?.ok_or(RecoveryError::StalePlan)?;
    if !matches!(
        workflow.state,
        RecoveryExecutionState::AwaitingEpochCommit
            | RecoveryExecutionState::EpochCommitted
            | RecoveryExecutionState::Rejoined
            | RecoveryExecutionState::AuditPending
    ) {
        return Err(RecoveryError::StalePlan);
    }
    let fixed_immutable = match (
        plan.body.source_authority_profile,
        plan.body.source_fixed_placement_policy,
    ) {
        (RecoveryAuthorityProfile::Dynamic, None) => false,
        (RecoveryAuthorityProfile::FixedImmutable, Some(_)) => true,
        _ => return Err(RecoveryError::StalePlan),
    };
    let staged_snapshot_name = workflow.staged_snapshot_name.as_deref();
    let mut latches = Vec::with_capacity(replicas.len());
    for replica in replicas {
        let token = super::replica_token(key, &replica.replica_id)?;
        let token_text = token.to_hex();
        let planned_evidence = plan
            .body
            .evidence
            .iter()
            .find(|evidence| evidence.replica_token == token)
            .ok_or(RecoveryError::StalePlan)?;
        let target_install = plan.body.target_tokens.contains(&token);
        let expected_database_identity = workflow
            .target_database_identities
            .get(&token_text)
            .copied()
            .or_else(|| (!target_install).then_some(planned_evidence.file_identity))
            .ok_or(RecoveryError::StalePlan)?;
        let paths = validate_bound_replica_path(key, plan, replica)?;
        let database =
            PinnedSnapshotFile::open(&paths.database).map_err(|_| RecoveryError::BackupCorrupt)?;
        if pinned_file_identity(key, &database)? != expected_database_identity {
            return Err(RecoveryError::BackupCorrupt);
        }
        database
            .verify_path_identity(&paths.database)
            .map_err(|_| RecoveryError::BackupCorrupt)?;
        // Once the common Rejoined proof is durable, only a locally
        // Consumed latch may move on to a newer selected snapshot.  Ask the
        // sidecar on this held database descriptor; never infer this from a
        // workflow state or another replica's consumption.
        let historical_consumed = workflow_allows_historical_consumed_latch(
            plan,
            &workflow,
            &paths.database,
            &database.file,
        )?;
        let expected_snapshot_identity = if target_install {
            workflow
                .target_snapshot_identities
                .get(&token_text)
                .copied()
                .ok_or(RecoveryError::BackupCorrupt)?
        } else {
            planned_evidence.current_snapshot_identity
        };
        let snapshot = current_snapshot_reference_from_pinned(
            &database,
            plan.body.identity,
            &paths.snapshots,
            limits,
            None,
        )
        .map_err(|_| RecoveryError::BackupCorrupt)?;
        let (snapshot_path, snapshot, snapshot_identity, snapshot_digest) = match snapshot {
            Some(mut snapshot) => {
                if snapshot.fixed_immutable != fixed_immutable {
                    return Err(RecoveryError::BackupCorrupt);
                }
                let identity = pinned_file_identity(key, &snapshot.file)?;
                if !historical_consumed && Some(identity) != expected_snapshot_identity {
                    return Err(RecoveryError::BackupCorrupt);
                }
                let digest = digest_pinned_file(&mut snapshot.file, limits.max_snapshot_bytes())?.0;
                if !historical_consumed
                    && target_install
                    && Some(digest) != workflow.staged_snapshot_digest
                {
                    return Err(RecoveryError::BackupCorrupt);
                }
                let snapshot_path = paths.snapshots.join(&snapshot.file_name);
                snapshot
                    .file
                    .verify_path_identity(&snapshot_path)
                    .map_err(|_| RecoveryError::BackupCorrupt)?;
                (
                    Some(snapshot_path),
                    Some(snapshot.file),
                    Some(identity),
                    Some(digest),
                )
            }
            None => {
                if !historical_consumed
                    && (expected_snapshot_identity.is_some()
                        || (target_install && workflow.staged_snapshot_digest.is_some()))
                {
                    return Err(RecoveryError::BackupCorrupt);
                }
                (None, None, None, None)
            }
        };
        latches.push(FleetLatchPin {
            replica,
            replica_token: token,
            database_path: paths.database,
            database,
            database_identity: expected_database_identity,
            snapshot_path,
            snapshot,
            snapshot_identity,
            snapshot_digest,
            fixed_immutable,
            target_install,
        });
    }
    let mut targets = Vec::with_capacity(plan.body.target_tokens.len());
    for target_token in &plan.body.target_tokens {
        let replica = replicas
            .iter()
            .find(|replica| {
                super::replica_token(key, &replica.replica_id).ok() == Some(*target_token)
            })
            .ok_or(RecoveryError::StalePlan)?;
        let token = target_token.to_hex();
        if workflow.target_installs.get(&token) != Some(&TargetInstallState::DatabaseInstalled) {
            return Err(RecoveryError::BackupCorrupt);
        }
        let expected_database_identity = workflow
            .target_database_identities
            .get(&token)
            .copied()
            .ok_or(RecoveryError::BackupCorrupt)?;
        let expected_snapshot_identity = workflow
            .target_snapshot_identities
            .get(&token)
            .copied()
            .ok_or(RecoveryError::BackupCorrupt)?;
        let paths = validate_bound_replica_path(key, plan, replica)?;
        let database =
            PinnedSnapshotFile::open(&paths.database).map_err(|_| RecoveryError::BackupCorrupt)?;
        if pinned_file_identity(key, &database)? != expected_database_identity {
            return Err(RecoveryError::BackupCorrupt);
        }
        database
            .verify_path_identity(&paths.database)
            .map_err(|_| RecoveryError::BackupCorrupt)?;
        let historical_consumed = workflow_allows_historical_consumed_latch(
            plan,
            &workflow,
            &paths.database,
            &database.file,
        )?;
        let (snapshot_path, snapshot, snapshot_identity, snapshot_digest) = if historical_consumed {
            // The consumed tombstone is a historical proof boundary.  Its
            // successor may have published an ordinary snapshot, so pin the
            // currently selected file and let the terminal proof authenticate
            // its lineage below.  Active/Pending paths stay on the exact
            // staged name and digest branch.
            match current_snapshot_reference_from_pinned(
                &database,
                plan.body.identity,
                &paths.snapshots,
                limits,
                None,
            )? {
                Some(mut snapshot) => {
                    if snapshot.fixed_immutable != fixed_immutable {
                        return Err(RecoveryError::BackupCorrupt);
                    }
                    let path = paths.snapshots.join(&snapshot.file_name);
                    let identity = pinned_file_identity(key, &snapshot.file)?;
                    let digest =
                        digest_pinned_file(&mut snapshot.file, limits.max_snapshot_bytes())?.0;
                    snapshot
                        .file
                        .verify_path_identity(&path)
                        .map_err(|_| RecoveryError::BackupCorrupt)?;
                    (
                        Some(path),
                        Some(snapshot.file),
                        Some(identity),
                        Some(digest),
                    )
                }
                None => (None, None, None, None),
            }
        } else {
            match staged_snapshot_name {
                Some(name) => {
                    validate_snapshot_name(name)?;
                    let path = paths.snapshots.join(name);
                    let mut file = PinnedSnapshotFile::open(&path)
                        .map_err(|_| RecoveryError::BackupCorrupt)?;
                    if fixed_immutable {
                        measure_fixed_snapshot_file(&file)?;
                    }
                    let digest = digest_pinned_file(&mut file, limits.max_snapshot_bytes())?.0;
                    let identity = pinned_file_identity(key, &file)?;
                    if Some(digest) != workflow.staged_snapshot_digest
                        || Some(identity) != expected_snapshot_identity
                    {
                        return Err(RecoveryError::BackupCorrupt);
                    }
                    file.verify_path_identity(&path)
                        .map_err(|_| RecoveryError::BackupCorrupt)?;
                    (Some(path), Some(file), Some(identity), Some(digest))
                }
                None => {
                    if expected_snapshot_identity.is_some()
                        || workflow.staged_snapshot_digest.is_some()
                        || workflow.staged_snapshot_identity.is_some()
                    {
                        return Err(RecoveryError::BackupCorrupt);
                    }
                    (None, None, None, None)
                }
            }
        };
        targets.push(FinalizationTargetPin {
            replica,
            database_path: paths.database,
            database,
            database_identity: expected_database_identity,
            snapshot_path,
            snapshot,
            snapshot_identity,
            snapshot_digest,
            fixed_immutable,
        });
    }
    Ok(FinalizationPins {
        targets,
        latches,
        legacy_predecessor: None,
        terminal_proof: workflow.terminal_proof,
    })
}

/// Return the sealed post-bootstrap predecessor for a legacy plan.  Legacy
/// plan evidence intentionally has no OpenRaft baseline; accepting whatever
/// current state happens to exist at each retry would let a queued runtime
/// command become the V2 predecessor.  Capture one uniform, descriptor-bound
/// bootstrap state before the first proposal and MAC it into the workflow.
pub(super) fn legacy_finalization_predecessor(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    pins: &mut FinalizationPins<'_>,
    backup_root: &Path,
    limits: RecoveryLimits,
) -> Result<Option<FinalizationPredecessorCapsule>, RecoveryError> {
    if !matches!(
        plan.body.basis,
        RecoveryDecisionBasis::ExplicitLegacyCheckpoint
    ) {
        return Ok(None);
    }
    if let Some(capsule) = pins.legacy_predecessor.as_ref() {
        return Ok(Some(capsule.clone()));
    }
    let directory = workflow_directory(backup_root, plan, false)?;
    let mut workflow = read_workflow(key, plan, &directory)?.ok_or(RecoveryError::StalePlan)?;
    if let Some(sealed) = workflow.legacy_finalization_predecessor.as_ref() {
        // The bootstrap predecessor exists only before the first V2 entry.
        // On every resume after proposal/application, current evidence has a
        // V2 suffix and therefore must be proved against this sealed capsule,
        // not recaptured as though it were still bootstrap-only.  Do not
        // inspect it here in a separate transaction: each later classifier
        // proof checks this capsule inside the same WAL snapshot as its
        // installed/finalized predicate.
        pins.legacy_predecessor = Some(sealed.clone());
        return Ok(Some(sealed.clone()));
    }
    let observed = capture_legacy_bootstrap_predecessor(key, plan, pins, limits)?;
    // This is the durable retry boundary.  A process loss after the write
    // reuses these exact fields; one before it simply re-captures only if the
    // same held descriptors still prove the canonical bootstrap state.
    workflow.legacy_finalization_predecessor = Some(observed.clone());
    write_workflow(key, &directory, &workflow)?;
    pins.legacy_predecessor = Some(observed.clone());
    Ok(Some(observed))
}

/// Result of checking a sealed legacy predecessor in a descriptor-bound WAL
/// snapshot.  Physical retention is the normal case.  A missing predecessor
/// is admissible only after this same snapshot has authenticated the complete
/// historical V2 terminal effect through the sealed terminal proof.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LegacyBootstrapMembershipProof {
    Retained,
    AuthenticatedPostTerminalCompaction,
}

/// Check the exact physical authority recorded in a sealed legacy capsule on
/// the transaction that is about to classify the installed/finalized state.
/// In particular, do not move this check to a prepass: another same-inode WAL
/// writer could otherwise replace the baseline between the physical and
/// semantic proofs.  The returned compaction exception has already proved the
/// terminal certificate, outcome, purge, and snapshot lineage on `conn`.
fn verify_legacy_bootstrap_membership_capsule_in_snapshot(
    plan: &RecoveryPlan,
    predecessor: &FinalizationPredecessorCapsule,
    terminal_proof: Option<&RecoveryTerminalProofV1>,
    evidence: &RecoveryReplicaEvidence,
    conn: &Connection,
    limits: RecoveryLimits,
    phase: FinalizedRecoveryV2ProofPhase,
) -> Result<LegacyBootstrapMembershipProof, RecoveryError> {
    let legacy_bootstrap = predecessor
        .legacy_bootstrap_membership
        .as_ref()
        // Version-7 capsules created before this field existed may have used
        // the Membership itself as the immediate predecessor.  That form is
        // still exactly re-provable; a `None` immediate commitment requires
        // the separately sealed physical bootstrap proof.
        .cloned()
        .or_else(|| {
            predecessor
                .bootstrap_membership_digest
                .map(|digest| LegacyBootstrapMembershipCapsule {
                    log_id: predecessor.baseline_log_id,
                    digest,
                })
        })
        .ok_or(RecoveryError::BackupCorrupt)?;
    let predecessor_kind = consensus::operator_recovery_v2_predecessor_kind_sync(
        conn,
        plan.body.identity,
        &predecessor.baseline_log_id,
    )
    .map_err(|_| RecoveryError::BackupCorrupt)?;
    let predecessor_matches = match predecessor_kind {
        consensus::OperatorRecoveryV2PredecessorKind::RetainedMembership(observed) => {
            predecessor.bootstrap_membership_digest == Some(RecoveryDigest::from_bytes(observed))
        }
        consensus::OperatorRecoveryV2PredecessorKind::RetainedNonMembership => {
            predecessor.bootstrap_membership_digest.is_none()
        }
        consensus::OperatorRecoveryV2PredecessorKind::NotRetained => false,
    };
    if matches!(
        predecessor_kind,
        consensus::OperatorRecoveryV2PredecessorKind::NotRetained
    ) {
        // Physical predecessor absence is not a generic retry exception.  It
        // is available only after terminal release, and only when this exact
        // SQLite snapshot proves the sealed historical V2 effect that binds
        // the capsule to its certificate, outcome, purge, and snapshot.
        if !matches!(phase, FinalizedRecoveryV2ProofPhase::PostTerminalHistorical) {
            return Err(RecoveryError::BackupCorrupt);
        }
        let terminal_proof = terminal_proof.ok_or(RecoveryError::BackupCorrupt)?;
        verify_exact_finalized_recovery_v2(
            plan,
            evidence,
            conn,
            limits,
            phase,
            Some(predecessor),
            Some(terminal_proof),
        )?;
        return Ok(LegacyBootstrapMembershipProof::AuthenticatedPostTerminalCompaction);
    }
    if !predecessor_matches {
        return Err(RecoveryError::BackupCorrupt);
    }
    let observed = consensus::operator_recovery_v2_bootstrap_membership_digest_sync(
        conn,
        plan.body.identity,
        &legacy_bootstrap.log_id,
    )
    .map_err(|_| RecoveryError::BackupCorrupt)?;
    if RecoveryDigest::from_bytes(observed) != legacy_bootstrap.digest {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(LegacyBootstrapMembershipProof::Retained)
}

fn capture_legacy_bootstrap_predecessor(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    pins: &mut FinalizationPins<'_>,
    limits: RecoveryLimits,
) -> Result<FinalizationPredecessorCapsule, RecoveryError> {
    if pins.latches.len() != plan.body.evidence.len()
        || pins.latches.iter().any(|pin| !pin.target_install)
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    let mut captured = None;
    for pin in &mut pins.latches {
        if pinned_file_identity(key, &pin.database)? != pin.database_identity {
            return Err(RecoveryError::BackupCorrupt);
        }
        pin.database
            .verify_path_identity(&pin.database_path)
            .map_err(|_| RecoveryError::BackupCorrupt)?;
        let (_evidence, candidate) = inspect_replica_from_pinned_with(
            InspectionInput {
                key,
                replica: pin.replica,
                identity: plan.body.identity,
                expected_members: &plan.body.expected_members,
                limits,
            },
            canonical_replica_paths(pin.replica, false)?,
            &pin.database,
            pin.snapshot.as_mut(),
            |evidence, conn| {
                legacy_bootstrap_predecessor_from_evidence(conn, plan, evidence, limits)
            },
        )?;
        match &captured {
            Some(expected) if expected != &candidate => return Err(RecoveryError::BackupCorrupt),
            Some(_) => {}
            None => captured = Some(candidate),
        }
    }
    captured.ok_or(RecoveryError::BackupCorrupt)
}

fn legacy_bootstrap_predecessor_from_evidence(
    conn: &Connection,
    plan: &RecoveryPlan,
    evidence: &RecoveryReplicaEvidence,
    limits: RecoveryLimits,
) -> Result<FinalizationPredecessorCapsule, RecoveryError> {
    let baseline = evidence
        .committed_log_id
        .ok_or(RecoveryError::BackupCorrupt)?;
    if evidence.applied_log_id != Some(baseline)
        || evidence.local_head_log_id != Some(baseline)
        || evidence.pending_recovery_epoch != Some(plan.body.next_recovery_epoch)
        || evidence.pending_plan_digest != Some(plan.plan_digest)
        || consensus::read_purged_sync(conn, plan.body.identity)
            .map_err(|_| RecoveryError::BackupCorrupt)?
            .is_some()
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    let end = baseline
        .index
        .checked_add(1)
        .ok_or(RecoveryError::BackupCorrupt)?;
    let count = usize::try_from(end).map_err(|_| RecoveryError::WorkLimitExceeded)?;
    if u64::try_from(count).map_err(|_| RecoveryError::WorkLimitExceeded)? > limits.max_rows() {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    let entries = consensus::read_log_range_for_recovery_sync(
        conn,
        plan.body.identity,
        0,
        Some(end),
        Some(count),
    )
    .map_err(|_| RecoveryError::BackupCorrupt)?;
    if entries.len() != count {
        return Err(RecoveryError::BackupCorrupt);
    }
    let mut expected_index = 0_u64;
    let mut bootstrap_membership = None;
    for entry in entries {
        if entry.log_id.index != expected_index {
            return Err(RecoveryError::BackupCorrupt);
        }
        expected_index = expected_index
            .checked_add(1)
            .ok_or(RecoveryError::BackupCorrupt)?;
        match entry.payload {
            opc_consensus::engine::EntryPayload::Blank if bootstrap_membership.is_some() => {}
            opc_consensus::engine::EntryPayload::Membership(payload)
                if bootstrap_membership.is_none() =>
            {
                let stored = opc_consensus::engine::StoredMembership::new(
                    Some(entry.log_id),
                    payload.clone(),
                );
                let members = stored
                    .nodes()
                    .map(|(node_id, _)| *node_id)
                    .collect::<BTreeSet<_>>();
                let config = stored.membership().get_joint_config();
                if config.len() != 1
                    || config.first() != Some(&plan.body.expected_members)
                    || members != plan.body.expected_members
                    || stored.membership().learner_ids().next().is_some()
                {
                    return Err(RecoveryError::BackupCorrupt);
                }
                let digest = RecoveryDigest::from_bytes(
                    consensus::operator_recovery_v2_bootstrap_membership_digest_sync(
                        conn,
                        plan.body.identity,
                        &entry.log_id,
                    )
                    .map_err(|_| RecoveryError::BackupCorrupt)?,
                );
                bootstrap_membership = Some(LegacyBootstrapMembershipCapsule {
                    log_id: entry.log_id,
                    digest,
                });
            }
            _ => return Err(RecoveryError::BackupCorrupt),
        }
    }
    let bootstrap_membership = bootstrap_membership.ok_or(RecoveryError::BackupCorrupt)?;
    let predecessor_bootstrap_membership_digest =
        match consensus::operator_recovery_v2_predecessor_kind_sync(
            conn,
            plan.body.identity,
            &baseline,
        )
        .map_err(|_| RecoveryError::BackupCorrupt)?
        {
            consensus::OperatorRecoveryV2PredecessorKind::RetainedMembership(digest) => {
                Some(RecoveryDigest::from_bytes(digest))
            }
            consensus::OperatorRecoveryV2PredecessorKind::RetainedNonMembership => None,
            consensus::OperatorRecoveryV2PredecessorKind::NotRetained => {
                return Err(RecoveryError::BackupCorrupt);
            }
        };
    let scope = consensus::read_membership_scope_sync(conn, plan.body.identity)
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    if scope.current_identity != plan.body.identity
        || scope.current_members != plan.body.expected_members
        || scope.application_authority_members != plan.body.expected_members
        || scope.pending.is_some()
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(FinalizationPredecessorCapsule {
        recovery_epoch: evidence.recovery_epoch,
        last_plan_digest: evidence.last_plan_digest,
        watch_cursor_invalidation_floor: evidence.watch_cursor_invalidation_floor,
        baseline_log_id: baseline,
        application_sequence: evidence.application_sequence,
        machine_last_digest: evidence.machine_last_digest,
        machine_logical_time: evidence.machine_logical_time,
        watch_sequence: evidence.watch_sequence,
        authority_commitment: evidence.authority_commitment,
        recovery_v2_invariant_state_digest: evidence.recovery_v2_invariant_state_digest,
        bootstrap_membership_digest: predecessor_bootstrap_membership_digest,
        legacy_bootstrap_membership: Some(bootstrap_membership),
    })
}

/// Revalidate the held finalization descriptors on either side of every
/// irreversible operation.  This catches replacement even when the bytes are
/// identical, while descriptor-backed inspection verifies authority and the
/// protected roster on the same inode that remains pinned.
pub(super) fn revalidate_finalization_pins(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    pins: &mut FinalizationPins<'_>,
    limits: RecoveryLimits,
    finalized: bool,
) -> Result<(), RecoveryError> {
    match (
        classify_finalization_pins_with_phase(key, plan, pins, limits)?,
        finalized,
    ) {
        (FinalizationTransitionState::AllInstalled, false)
        | (FinalizationTransitionState::AllFinalized, true) => Ok(()),
        _ => Err(RecoveryError::BackupCorrupt),
    }
}

/// Revalidate the retained fleet descriptors immediately after the live core
/// atomically consumes Terminal(PendingHandoff).  Consumption is the service
/// release boundary: retain exact marker/outcome authority, but allow later
/// ordinary commands that can now legitimately follow the recovery V2 entry.
pub(super) fn revalidate_finalization_pins_after_terminal_consumed(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    pins: &mut FinalizationPins<'_>,
    limits: RecoveryLimits,
) -> Result<(), RecoveryError> {
    match classify_finalization_pins_with_phase(key, plan, pins, limits)? {
        FinalizationTransitionState::AllFinalized => Ok(()),
        _ => Err(RecoveryError::BackupCorrupt),
    }
}

/// Prove that every held fleet descriptor is one of the two exact,
/// authenticated states permitted while the epoch command replicates.  This
/// does not loosen finalization: callers may advance only from
/// `AllFinalized`; `MixedConverging` is solely a retryable availability state.
pub(super) fn classify_finalization_pins(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    pins: &mut FinalizationPins<'_>,
    limits: RecoveryLimits,
) -> Result<FinalizationTransitionState, RecoveryError> {
    classify_finalization_pins_with_phase(key, plan, pins, limits)
}

#[derive(Clone, Copy)]
enum FinalizationReplicaProof {
    Finalized,
    Installed,
    ExactFinalizeInFlight,
}

fn classify_finalization_pins_with_phase(
    key: &RecoveryIntegrityKey,
    plan: &RecoveryPlan,
    pins: &mut FinalizationPins<'_>,
    limits: RecoveryLimits,
) -> Result<FinalizationTransitionState, RecoveryError> {
    #[cfg(test)]
    run_legacy_classification_before_proof_hook();
    let legacy_predecessor = pins.legacy_predecessor.clone();
    let terminal_proof = pins.terminal_proof.clone();
    // Take the raw descriptor-bound fleet observation before any semantic
    // installed/finalized proof.  In particular, the durable terminal proof
    // does not make a PendingHandoff sidecar historical while every member is
    // still unconsumed.
    let sidecar_phases = finalization_fleet_latch_sidecar_phases(plan, &pins.latches)?;
    let fleet_phase = finalization_fleet_proof_phase(&sidecar_phases, terminal_proof.as_ref())?;
    let mut saw_installed = false;
    let mut saw_inflight = false;
    let mut saw_finalized = false;
    for latch in &mut pins.latches {
        if pinned_file_identity(key, &latch.database)? != latch.database_identity {
            return Err(RecoveryError::BackupCorrupt);
        }
        latch
            .database
            .verify_path_identity(&latch.database_path)
            .map_err(|_| RecoveryError::BackupCorrupt)?;
        match (
            latch.snapshot_path.as_deref(),
            latch.snapshot.as_mut(),
            latch.snapshot_identity,
            latch.snapshot_digest,
        ) {
            (Some(path), Some(file), Some(identity), digest) => {
                if latch.fixed_immutable {
                    measure_fixed_snapshot_file(file)?;
                }
                let observed_digest = digest_pinned_file(file, limits.max_snapshot_bytes())?.0;
                if pinned_file_identity(key, file)? != identity
                    || digest.is_some_and(|expected| observed_digest != expected)
                {
                    return Err(RecoveryError::BackupCorrupt);
                }
                file.verify_path_identity(path)
                    .map_err(|_| RecoveryError::BackupCorrupt)?;
            }
            (None, None, None, None) => {}
            _ => return Err(RecoveryError::BackupCorrupt),
        }
        // Targets are semantically checked below against the installed and
        // finalized workflow predicates.  Every untouched voter still needs
        // descriptor-backed semantic proof before its fleet latch can be
        // changed: otherwise an in-place authority/roster mutation could
        // inherit a successful target finalization.
        if !latch.target_install {
            let planned = plan
                .body
                .evidence
                .iter()
                .find(|item| item.replica_token == latch.replica_token)
                .ok_or(RecoveryError::StalePlan)?;
            let (_evidence, proof) = inspect_replica_from_pinned_with(
                InspectionInput {
                    key,
                    replica: latch.replica,
                    identity: plan.body.identity,
                    expected_members: &plan.body.expected_members,
                    limits,
                },
                canonical_replica_paths(latch.replica, false)?,
                &latch.database,
                latch.snapshot.as_mut(),
                |evidence, conn| {
                    if let Some(predecessor) = legacy_predecessor.as_ref() {
                        match verify_legacy_bootstrap_membership_capsule_in_snapshot(
                            plan,
                            predecessor,
                            terminal_proof.as_ref(),
                            evidence,
                            conn,
                            limits,
                            fleet_phase,
                        )? {
                            LegacyBootstrapMembershipProof::Retained => {}
                            LegacyBootstrapMembershipProof::AuthenticatedPostTerminalCompaction => {
                                return Ok(FinalizationReplicaProof::Finalized);
                            }
                        }
                    }
                    if verify_exact_finalized_recovery_v2(
                        plan,
                        evidence,
                        conn,
                        limits,
                        fleet_phase,
                        legacy_predecessor.as_ref(),
                        terminal_proof.as_ref(),
                    )
                    .is_ok()
                    {
                        return Ok(FinalizationReplicaProof::Finalized);
                    }
                    match verify_untargeted_installed_evidence(
                        plan, planned, evidence, conn, limits,
                    ) {
                        Ok(UnappliedRecoveryFinalizePhase::NoFinalize) => {
                            Ok(FinalizationReplicaProof::Installed)
                        }
                        Ok(UnappliedRecoveryFinalizePhase::ExactFinalizeInFlight) => {
                            Ok(FinalizationReplicaProof::ExactFinalizeInFlight)
                        }
                        Err(_) => Err(RecoveryError::BackupCorrupt),
                    }
                },
            )
            .map_err(|error| match error {
                // Finalization is proving an already-installed, sealed
                // recovery transaction. A malformed retained voter is not a
                // fresh source-inspection finding: it invalidates the sealed
                // terminal proof and must use the workflow corruption result.
                RecoveryError::CorruptReplica => RecoveryError::BackupCorrupt,
                error => error,
            })?;
            match proof {
                FinalizationReplicaProof::Finalized => saw_finalized = true,
                FinalizationReplicaProof::Installed => saw_installed = true,
                FinalizationReplicaProof::ExactFinalizeInFlight => saw_inflight = true,
            }
        }
    }
    for target in &mut pins.targets {
        if pinned_file_identity(key, &target.database)? != target.database_identity {
            return Err(RecoveryError::BackupCorrupt);
        }
        target
            .database
            .verify_path_identity(&target.database_path)
            .map_err(|_| RecoveryError::BackupCorrupt)?;
        match (
            target.snapshot_path.as_deref(),
            target.snapshot.as_mut(),
            target.snapshot_identity,
            target.snapshot_digest,
        ) {
            (Some(path), Some(file), Some(identity), Some(digest)) => {
                if target.fixed_immutable {
                    measure_fixed_snapshot_file(file)?;
                }
                if digest_pinned_file(file, limits.max_snapshot_bytes())?.0 != digest
                    || pinned_file_identity(key, file)? != identity
                {
                    return Err(RecoveryError::BackupCorrupt);
                }
                file.verify_path_identity(path)
                    .map_err(|_| RecoveryError::BackupCorrupt)?;
            }
            (None, None, None, None) => {}
            _ => return Err(RecoveryError::BackupCorrupt),
        }
        let source = plan
            .body
            .evidence
            .iter()
            .find(|item| item.replica_token == plan.body.source_token)
            .ok_or(RecoveryError::StalePlan)?;
        let (_evidence, proof) = inspect_replica_from_pinned_with(
            InspectionInput {
                key,
                replica: target.replica,
                identity: plan.body.identity,
                expected_members: &plan.body.expected_members,
                limits,
            },
            canonical_replica_paths(target.replica, false)?,
            &target.database,
            target.snapshot.as_mut(),
            |evidence, conn| {
                if let Some(predecessor) = legacy_predecessor.as_ref() {
                    match verify_legacy_bootstrap_membership_capsule_in_snapshot(
                        plan,
                        predecessor,
                        terminal_proof.as_ref(),
                        evidence,
                        conn,
                        limits,
                        fleet_phase,
                    )? {
                        LegacyBootstrapMembershipProof::Retained => {}
                        LegacyBootstrapMembershipProof::AuthenticatedPostTerminalCompaction => {
                            return Ok(FinalizationReplicaProof::Finalized);
                        }
                    }
                }
                if verify_exact_finalized_recovery_v2(
                    plan,
                    evidence,
                    conn,
                    limits,
                    fleet_phase,
                    legacy_predecessor.as_ref(),
                    terminal_proof.as_ref(),
                )
                .is_ok()
                {
                    return Ok(FinalizationReplicaProof::Finalized);
                }
                if let Some(predecessor) = legacy_predecessor.as_ref() {
                    verify_legacy_target_installed_evidence(plan, evidence, predecessor)
                        .map_err(|_| RecoveryError::BackupCorrupt)?;
                    return match verify_legacy_exact_unapplied_recovery_finalize_suffix(
                        plan,
                        predecessor,
                        evidence,
                        conn,
                        limits,
                    ) {
                        Ok(UnappliedRecoveryFinalizePhase::NoFinalize) => {
                            Ok(FinalizationReplicaProof::Installed)
                        }
                        Ok(UnappliedRecoveryFinalizePhase::ExactFinalizeInFlight) => {
                            Ok(FinalizationReplicaProof::ExactFinalizeInFlight)
                        }
                        Err(_) => Err(RecoveryError::BackupCorrupt),
                    };
                }
                verify_target_installed_evidence(plan, evidence)
                    .map_err(|_| RecoveryError::BackupCorrupt)?;
                match verify_exact_unapplied_recovery_finalize_suffix(
                    plan, source, evidence, conn, limits,
                ) {
                    Ok(UnappliedRecoveryFinalizePhase::NoFinalize) => {
                        Ok(FinalizationReplicaProof::Installed)
                    }
                    Ok(UnappliedRecoveryFinalizePhase::ExactFinalizeInFlight) => {
                        Ok(FinalizationReplicaProof::ExactFinalizeInFlight)
                    }
                    Err(_) => Err(RecoveryError::BackupCorrupt),
                }
            },
        )
        .map_err(|error| match error {
            RecoveryError::CorruptReplica => RecoveryError::BackupCorrupt,
            error => error,
        })?;
        match proof {
            FinalizationReplicaProof::Finalized => saw_finalized = true,
            FinalizationReplicaProof::Installed => saw_installed = true,
            FinalizationReplicaProof::ExactFinalizeInFlight => saw_inflight = true,
        }
    }
    // Re-pin every raw sidecar after the complete proof.  A phase transition
    // during another replica's proof cannot be treated as if the earlier
    // phase were still authoritative on retry: Active -> PendingHandoff must
    // be rejected even though both states are strict before the first
    // Consumed sidecar exists.
    let final_sidecar_phases = finalization_fleet_latch_sidecar_phases(plan, &pins.latches)?;
    if final_sidecar_phases != sidecar_phases
        || finalization_fleet_proof_phase(&final_sidecar_phases, terminal_proof.as_ref())?
            != fleet_phase
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    if saw_inflight {
        return Ok(FinalizationTransitionState::ExactFinalizeInFlight);
    }
    match (saw_installed, saw_finalized) {
        (true, false) => Ok(FinalizationTransitionState::AllInstalled),
        (false, true) => Ok(FinalizationTransitionState::AllFinalized),
        (true, true) => Ok(FinalizationTransitionState::MixedConverging),
        // A well-formed plan always has at least one target.  Treat an empty
        // descriptor set as corrupt rather than granting a vacuous epoch
        // transition.
        (false, false) => Err(RecoveryError::BackupCorrupt),
    }
}

fn current_snapshot_reference_from_pinned(
    database: &PinnedSnapshotFile,
    identity: SessionConsensusIdentity,
    snapshot_dir: &Path,
    limits: RecoveryLimits,
    pinned_snapshot: Option<PinnedSnapshotFile>,
) -> Result<Option<SnapshotReference>, RecoveryError> {
    let conn = open_read_only_pinned(database)?;
    if !table_exists(&conn, "consensus_identity")? {
        return Ok(None);
    }
    let storage_identity =
        consensus::read_storage_identity_sync(&conn).map_err(|_| RecoveryError::CorruptReplica)?;
    let scope = consensus::read_membership_scope_sync(&conn, storage_identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if scope.current_identity != identity {
        return Err(RecoveryError::WrongCluster);
    }
    let snapshot = consensus::read_current_snapshot_sync(&conn, storage_identity)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let Some((_, file_name, expected_checksum, expected_length)) = snapshot else {
        if pinned_snapshot.is_some() {
            return Err(RecoveryError::BackupCorrupt);
        }
        return Ok(None);
    };
    validate_snapshot_name(&file_name)?;
    let path = snapshot_dir.join(&file_name);
    let mut file = pinned_snapshot
        .unwrap_or(PinnedSnapshotFile::open(&path).map_err(|_| RecoveryError::CorruptReplica)?);
    let fixed_immutable = fixed_immutable_profile(&conn)?;
    if fixed_immutable {
        measure_fixed_snapshot_file(&file)?;
    }
    let (checksum, length) =
        verify_pinned_snapshot_file(&mut file, limits.max_snapshot_bytes(), None)?;
    if checksum != expected_checksum || length != expected_length {
        return Err(RecoveryError::CorruptReplica);
    }
    file.verify_path_identity(&path)?;
    Ok(Some(SnapshotReference {
        file_name,
        file,
        fixed_immutable,
    }))
}

/// Read the exact persisted authority descriptor.  Both columns are required
/// even for dynamic replicas: omitting a field must not silently default an
/// offline recovery campaign to a weaker transport policy.
fn recovery_authority_descriptor(
    conn: &Connection,
) -> Result<
    (
        RecoveryAuthorityProfile,
        Option<RecoveryFixedPlacementPolicy>,
    ),
    RecoveryError,
> {
    let columns: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('consensus_identity') WHERE name IN ('authority_profile', 'fixed_placement_policy')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if columns != 2 {
        return Err(RecoveryError::CorruptReplica);
    }
    let (profile, policy): (Option<i64>, Option<i64>) = conn
        .query_row(
            "SELECT authority_profile, fixed_placement_policy FROM consensus_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| RecoveryError::CorruptReplica)?;
    match (profile, policy) {
        (Some(1), None) => Ok((RecoveryAuthorityProfile::Dynamic, None)),
        (Some(2), Some(1)) => Ok((
            RecoveryAuthorityProfile::FixedImmutable,
            Some(RecoveryFixedPlacementPolicy::RequireIndependentFailureDomains),
        )),
        (Some(2), Some(2)) => Ok((
            RecoveryAuthorityProfile::FixedImmutable,
            Some(RecoveryFixedPlacementPolicy::AllowReducedResilience),
        )),
        _ => Err(RecoveryError::CorruptReplica),
    }
}

/// Return whether this offline replica carries the fixed authority profile.
/// The profile and coupled placement policy are both authenticated above.
fn fixed_immutable_profile(conn: &Connection) -> Result<bool, RecoveryError> {
    Ok(matches!(
        recovery_authority_descriptor(conn)?,
        (RecoveryAuthorityProfile::FixedImmutable, Some(_))
    ))
}

#[cfg(test)]
fn snapshot_seal_policy(database: &Path) -> Result<bool, RecoveryError> {
    let conn = open_read_only(database)?;
    fixed_immutable_profile(&conn)
}

/// Read the staged authority descriptor through the held database descriptor.
/// `/proc/self/fd` is only the initial transport to SQLite: the bundled VFS
/// may canonicalize it before `xOpen`, so authenticate SQLite's actual main
/// descriptor before querying it.
#[cfg(target_os = "linux")]
fn snapshot_seal_policy_from_pinned_database(
    database: &PinnedSnapshotFile,
    plan: &RecoveryPlan,
) -> Result<bool, RecoveryError> {
    use std::os::fd::AsRawFd as _;

    let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", database.file.as_raw_fd()));
    let conn = Connection::open_with_flags(
        descriptor_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| RecoveryError::BackupCorrupt)?;
    verify_sqlite_main_file_binding(&database.file, &conn)
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    conn.execute_batch("PRAGMA query_only = ON; PRAGMA trusted_schema = OFF;")
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    let (profile, policy) = recovery_authority_descriptor(&conn)?;
    if profile != plan.body.source_authority_profile
        || policy != plan.body.source_fixed_placement_policy
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(profile == RecoveryAuthorityProfile::FixedImmutable)
}

#[cfg(not(target_os = "linux"))]
fn snapshot_seal_policy_from_pinned_database(
    _database: &PinnedSnapshotFile,
    _plan: &RecoveryPlan,
) -> Result<bool, RecoveryError> {
    Err(RecoveryError::BackupCorrupt)
}

fn staged_snapshot_evidence_from_pin(
    key: &RecoveryIntegrityKey,
    file: Option<&mut PinnedSnapshotFile>,
    staged_snapshot: &Path,
    source_snapshot_name: Option<&str>,
    limits: RecoveryLimits,
) -> Result<(Option<RecoveryDigest>, Option<RecoveryDigest>), RecoveryError> {
    let Some(name) = source_snapshot_name else {
        require_path_absent(staged_snapshot)?;
        if file.is_some() {
            return Err(RecoveryError::BackupCorrupt);
        }
        return Ok((None, None));
    };
    validate_snapshot_name(name)?;
    let file = file.ok_or(RecoveryError::BackupCorrupt)?;
    let digest = digest_pinned_file(file, limits.max_snapshot_bytes())?.0;
    let identity = pinned_file_identity(key, file)?;
    file.verify_path_identity(staged_snapshot)?;
    Ok((Some(digest), Some(identity)))
}

/// Open the staged snapshot once and retain that exact inode through every
/// target copy and installed-file comparison.  The workflow binds both its
/// content digest and inode MAC, so a later pathname substitution cannot
/// become a valid staged source.
fn open_authenticated_staged_snapshot(
    key: &RecoveryIntegrityKey,
    workflow: &WorkflowRecord,
    staged_snapshot: &Path,
    source_snapshot_name: Option<&str>,
    limits: RecoveryLimits,
) -> Result<Option<PinnedSnapshotFile>, RecoveryError> {
    let Some(name) = source_snapshot_name else {
        require_path_absent(staged_snapshot)?;
        if workflow.staged_snapshot_digest.is_some() || workflow.staged_snapshot_identity.is_some()
        {
            return Err(RecoveryError::BackupCorrupt);
        }
        return Ok(None);
    };
    validate_snapshot_name(name)?;
    let mut file = PinnedSnapshotFile::open(staged_snapshot)?;
    let digest = digest_pinned_file(&mut file, limits.max_snapshot_bytes())?.0;
    let identity = pinned_file_identity(key, &file)?;
    file.verify_path_identity(staged_snapshot)?;
    if Some(digest) != workflow.staged_snapshot_digest
        || Some(identity) != workflow.staged_snapshot_identity
    {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok(Some(file))
}

impl PinnedSnapshotFile {
    fn open(path: &Path) -> Result<Self, RecoveryError> {
        let file = open_regular_read(path).map_err(|_| RecoveryError::CorruptReplica)?;
        let metadata = file.metadata().map_err(|_| RecoveryError::CorruptReplica)?;
        if !metadata.is_file() {
            return Err(RecoveryError::CorruptReplica);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                file,
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Err(RecoveryError::InvalidRequest)
        }
    }

    /// Duplicate this already-admitted regular file without resolving a
    /// pathname. The duplicate preserves the original inode authority while
    /// allowing one consumer to copy the artifact and another to inspect the
    /// same checkpoint namespace.
    fn try_clone(&self) -> Result<Self, RecoveryError> {
        let file = self
            .file
            .try_clone()
            .map_err(|_| RecoveryError::FileOperationFailed)?;
        let metadata = file
            .metadata()
            .map_err(|_| RecoveryError::FileOperationFailed)?;
        if !metadata.is_file() {
            return Err(RecoveryError::FileOperationFailed);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.dev() != self.device || metadata.ino() != self.inode {
                return Err(RecoveryError::FileOperationFailed);
            }
            Ok(Self {
                file,
                device: self.device,
                inode: self.inode,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Err(RecoveryError::InvalidRequest)
        }
    }

    /// Re-resolve a pathname only to prove it still names this open inode.
    /// The descriptor, not the pathname, remains the input to every scan.
    fn verify_path_identity(&self, path: &Path) -> Result<(), RecoveryError> {
        let observed = open_regular_read(path).map_err(|_| RecoveryError::SourceChanged)?;
        let metadata = observed
            .metadata()
            .map_err(|_| RecoveryError::SourceChanged)?;
        if !metadata.is_file() {
            return Err(RecoveryError::SourceChanged);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.dev() != self.device || metadata.ino() != self.inode {
                return Err(RecoveryError::SourceChanged);
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Err(RecoveryError::InvalidRequest)
        }
    }

    /// Prove that this read-only pin names the inode created through `writer`.
    /// The pin is acquired before the writable descriptor is closed so there
    /// is no pathname-only interval between copying and fs-verity sealing.
    fn verify_writer_identity(&self, writer: &File) -> Result<(), RecoveryError> {
        let metadata = writer
            .metadata()
            .map_err(|_| RecoveryError::SourceChanged)?;
        if !metadata.is_file() {
            return Err(RecoveryError::SourceChanged);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.dev() != self.device || metadata.ino() != self.inode {
                return Err(RecoveryError::SourceChanged);
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Err(RecoveryError::InvalidRequest)
        }
    }
}

fn pinned_file_identity(
    key: &RecoveryIntegrityKey,
    file: &PinnedSnapshotFile,
) -> Result<RecoveryDigest, RecoveryError> {
    recovery_file_identity(key, &file.file)
}

fn digest_pinned_file(
    file: &mut PinnedSnapshotFile,
    max: u64,
) -> Result<(RecoveryDigest, u64), RecoveryError> {
    use std::io::{Seek, SeekFrom};

    let metadata = file
        .file
        .metadata()
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max {
        return Err(RecoveryError::BackupCorrupt);
    }
    file.file
        .seek(SeekFrom::Start(0))
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    let mut hasher = Sha256::new();
    hasher.update(FILE_DIGEST_DOMAIN);
    let length = hash_reader(&mut file.file, &mut hasher, max, None)?;
    if length != metadata.len() {
        return Err(RecoveryError::BackupCorrupt);
    }
    Ok((RecoveryDigest::from_bytes(hasher.finalize().into()), length))
}

/// Require an existing fixed fs-verity seal on a recovery source artifact.
/// A byte-identical but unsealed replacement is not equivalent evidence.
#[cfg(test)]
fn measure_fixed_snapshot(path: &Path) -> Result<(), RecoveryError> {
    let file = PinnedSnapshotFile::open(path)?;
    measure_fixed_snapshot_file(&file)
}

fn measure_fixed_snapshot_file(file: &PinnedSnapshotFile) -> Result<(), RecoveryError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsFd as _;

        opc_fs_verity_sys::measure_exact_profile(file.file.as_fd())
            .map_err(|_| RecoveryError::CorruptReplica)?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        Err(RecoveryError::CorruptReplica)
    }
}

/// Seal a freshly copied recovery snapshot after its writer has closed. This
/// is intentionally distinct from database copies: recovery later writes its
/// SQLite database, while snapshot envelopes are immutable transport objects.
#[cfg(test)]
fn seal_fixed_snapshot(path: &Path) -> Result<(), RecoveryError> {
    let file = PinnedSnapshotFile::open(path).map_err(|_| RecoveryError::FileOperationFailed)?;
    seal_fixed_snapshot_file(&file)
}

fn seal_fixed_snapshot_file(file: &PinnedSnapshotFile) -> Result<(), RecoveryError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsFd as _;

        opc_fs_verity_sys::enable_fixed_profile(file.file.as_fd())
            .map_err(|_| RecoveryError::FileOperationFailed)?;
        opc_fs_verity_sys::measure_exact_profile(file.file.as_fd())
            .map_err(|_| RecoveryError::FileOperationFailed)?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        Err(RecoveryError::FileOperationFailed)
    }
}

fn copy_snapshot_file_bounded(
    source: &mut PinnedSnapshotFile,
    destination: &Path,
    max: u64,
    fixed_immutable: bool,
) -> Result<PinnedSnapshotFile, RecoveryError> {
    use std::io::{Seek, SeekFrom};

    let source_metadata = source
        .file
        .metadata()
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    if !source_metadata.is_file() || source_metadata.len() == 0 || source_metadata.len() > max {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    source
        .file
        .seek(SeekFrom::Start(0))
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    let mut writer = private_create_new(destination)?;
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut copied = 0_u64;
    loop {
        let read = source
            .file
            .read(&mut buffer)
            .map_err(|_| RecoveryError::FileOperationFailed)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(u64::try_from(read).map_err(|_| RecoveryError::WorkLimitExceeded)?)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if copied > max {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|_| RecoveryError::FileOperationFailed)?;
    }
    if copied != source_metadata.len() {
        return Err(RecoveryError::SourceChanged);
    }
    writer
        .flush()
        .and_then(|_| writer.sync_all())
        .map_err(|_| RecoveryError::FileOperationFailed)?;

    // Acquire a read-only pin while the writer still owns the inode, and bind
    // the two descriptors before closing the writer. fs-verity requires the
    // writable descriptor to be closed, but pathname replacement must never
    // become the authority for choosing which object is sealed.
    let mut destination_file =
        PinnedSnapshotFile::open(destination).map_err(|_| RecoveryError::FileOperationFailed)?;
    destination_file
        .verify_writer_identity(&writer)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    destination_file
        .verify_path_identity(destination)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    drop(writer);
    if fixed_immutable {
        seal_fixed_snapshot_file(&destination_file)?;
    }
    verify_pinned_snapshot_file(&mut destination_file, max, None)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    destination_file
        .verify_path_identity(destination)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    Ok(destination_file)
}

fn verify_snapshot_file(
    path: &Path,
    max_bytes: u64,
    budget: Option<&InspectionBudget>,
) -> Result<([u8; 32], u64), RecoveryError> {
    let mut file = PinnedSnapshotFile::open(path)?;
    let verified = verify_pinned_snapshot_file(&mut file, max_bytes, budget)?;
    file.verify_path_identity(path)?;
    Ok(verified)
}

fn verify_pinned_snapshot_file(
    pinned: &mut PinnedSnapshotFile,
    max_bytes: u64,
    budget: Option<&InspectionBudget>,
) -> Result<([u8; 32], u64), RecoveryError> {
    if let Some(budget) = budget {
        budget.check()?;
    }
    let file = &mut pinned.file;
    let metadata = file.metadata().map_err(|_| RecoveryError::CorruptReplica)?;
    if !metadata.is_file()
        || metadata.len() <= SNAPSHOT_ENVELOPE_FOOTER_BYTES
        || metadata.len() > max_bytes
    {
        return Err(RecoveryError::CorruptReplica);
    }
    let total = metadata.len();
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::End(
        -i64::try_from(SNAPSHOT_ENVELOPE_FOOTER_BYTES)
            .map_err(|_| RecoveryError::CorruptReplica)?,
    ))
    .map_err(|_| RecoveryError::CorruptReplica)?;
    let mut footer = [0_u8; SNAPSHOT_ENVELOPE_FOOTER_BYTES as usize];
    file.read_exact(&mut footer)
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if &footer[..8] != SNAPSHOT_FOOTER_MAGIC {
        return Err(RecoveryError::CorruptReplica);
    }
    let length = u64::from_be_bytes(
        footer[8..16]
            .try_into()
            .map_err(|_| RecoveryError::CorruptReplica)?,
    );
    let expected: [u8; 32] = footer[16..]
        .try_into()
        .map_err(|_| RecoveryError::CorruptReplica)?;
    if length == 0 || length.checked_add(SNAPSHOT_ENVELOPE_FOOTER_BYTES) != Some(total) {
        return Err(RecoveryError::CorruptReplica);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| RecoveryError::CorruptReplica)?;
    let mut limited = file.take(length);
    let mut hasher = Sha256::new();
    let copied = hash_reader(&mut limited, &mut hasher, length, budget)?;
    let actual: [u8; 32] = hasher.finalize().into();
    if copied != length || actual != expected {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok((actual, total))
}

fn canonical_replica_paths(
    replica: &RecoveryReplica,
    allow_missing: bool,
) -> Result<CanonicalReplicaPaths, RecoveryError> {
    validate_path_text(&replica.database_path)?;
    validate_path_text(&replica.snapshot_directory)?;
    match fs::symlink_metadata(&replica.database_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            return Err(RecoveryError::InvalidRequest);
        }
        Ok(_) => {}
        Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(RecoveryError::DatabaseUnavailable),
    }
    let raw_snapshot_metadata = fs::symlink_metadata(&replica.snapshot_directory)
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    if raw_snapshot_metadata.file_type().is_symlink() || !raw_snapshot_metadata.file_type().is_dir()
    {
        return Err(RecoveryError::InvalidRequest);
    }
    let database = if allow_missing {
        replica.database_path.clone()
    } else {
        fs::canonicalize(&replica.database_path).map_err(|_| RecoveryError::DatabaseUnavailable)?
    };
    let snapshots = fs::canonicalize(&replica.snapshot_directory)
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    let database_metadata =
        fs::symlink_metadata(&database).map_err(|_| RecoveryError::DatabaseUnavailable)?;
    let snapshot_metadata =
        fs::symlink_metadata(&snapshots).map_err(|_| RecoveryError::DatabaseUnavailable)?;
    if database_metadata.file_type().is_symlink()
        || (!allow_missing && !database_metadata.file_type().is_file())
        || snapshot_metadata.file_type().is_symlink()
        || !snapshot_metadata.file_type().is_dir()
    {
        return Err(RecoveryError::InvalidRequest);
    }
    Ok(CanonicalReplicaPaths {
        database,
        snapshots,
    })
}

fn recovery_path_binding(
    key: &RecoveryIntegrityKey,
    paths: &CanonicalReplicaPaths,
) -> Result<RecoveryDigest, RecoveryError> {
    let database = paths
        .database
        .to_str()
        .ok_or(RecoveryError::InvalidRequest)?;
    let snapshots = paths
        .snapshots
        .to_str()
        .ok_or(RecoveryError::InvalidRequest)?;
    Ok(RecoveryDigest::from_bytes(plan_mac(
        key,
        PATH_BINDING_DOMAIN,
        &[database.as_bytes(), snapshots.as_bytes()],
    )?))
}

fn recovery_file_identity(
    key: &RecoveryIntegrityKey,
    file: &File,
) -> Result<RecoveryDigest, RecoveryError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsFd as _;
        // This is intentionally a crash-stable, comparison-only identity.
        // Mount IDs describe one Linux mount instance and must remain only a
        // live descriptor fence; timestamps and dev/inode are likewise not
        // sufficient when an unlinked inode is recycled.  The safe sys
        // boundary obtains an externally assigned filesystem UUID plus an
        // `AT_HANDLE_FID` opaque inode handle and fails closed when either is
        // unavailable.
        let persistent = opc_fs_verity_sys::persistent_file_identity(file.as_fd())
            .map_err(|_| RecoveryError::FileOperationFailed)?;
        Ok(RecoveryDigest::from_bytes(plan_mac(
            key,
            FILE_IDENTITY_DOMAIN,
            &[
                persistent.filesystem_uuid(),
                &persistent.handle_type().to_be_bytes(),
                persistent.handle_bytes(),
            ],
        )?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (key, file);
        Err(RecoveryError::InvalidRequest)
    }
}

fn validate_path_text(path: &Path) -> Result<(), RecoveryError> {
    let value = path.to_str().ok_or(RecoveryError::InvalidRequest)?;
    if value.is_empty() || value.len() > PATH_MAX_BYTES || value.chars().any(char::is_control) {
        return Err(RecoveryError::InvalidRequest);
    }
    Ok(())
}

#[cfg(test)]
fn open_read_only(path: &Path) -> Result<Connection, RecoveryError> {
    let metadata = fs::metadata(path).map_err(|_| RecoveryError::DatabaseUnavailable)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > SNAPSHOT_DATABASE_MAX_BYTES {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    conn.busy_timeout(SQLITE_BUSY_TIMEOUT)
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    consensus::snapshot_database_extent_sync(&conn)
        .map_err(|_| RecoveryError::WorkLimitExceeded)?;
    conn.execute_batch(
        "PRAGMA query_only = ON; PRAGMA trusted_schema = OFF; BEGIN DEFERRED TRANSACTION;",
    )
    .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    Ok(conn)
}

/// Prove that SQLite's VFS opened the same live and persistent file object as
/// the descriptor that authorized this recovery operation.  A procfs path is
/// not itself an identity proof: bundled SQLite canonicalizes it before
/// `xOpen`, which permits an attacker to exchange the public name between
/// canonicalization and the VFS open.  `main_file_descriptor` duplicates the
/// descriptor SQLite actually owns, without transferring VFS ownership.
#[cfg(target_os = "linux")]
fn verify_sqlite_main_file_binding(
    expected: &File,
    connection: &Connection,
) -> Result<(), RecoveryError> {
    use std::os::fd::AsFd as _;
    use std::os::unix::fs::MetadataExt as _;

    let observed = opc_sqlite_file_control_sys::main_file_descriptor(connection)
        .map_err(|_| RecoveryError::SourceChanged)?;
    let expected_metadata = expected
        .metadata()
        .map_err(|_| RecoveryError::SourceChanged)?;
    let observed_metadata = observed
        .metadata()
        .map_err(|_| RecoveryError::SourceChanged)?;
    if !expected_metadata.is_file()
        || !observed_metadata.is_file()
        || expected_metadata.dev() != observed_metadata.dev()
        || expected_metadata.ino() != observed_metadata.ino()
    {
        return Err(RecoveryError::SourceChanged);
    }

    // Device/inode is the live, same-mount fence.  Pair it with the stable
    // filesystem UUID + opaque file handle so an inode recycle cannot be
    // accepted as the same recovery object across the persistent boundary.
    let expected_persistent = opc_fs_verity_sys::persistent_file_identity(expected.as_fd())
        .map_err(|_| RecoveryError::SourceChanged)?;
    let observed_persistent = opc_fs_verity_sys::persistent_file_identity(observed.as_fd())
        .map_err(|_| RecoveryError::SourceChanged)?;
    if expected_persistent != observed_persistent {
        return Err(RecoveryError::SourceChanged);
    }
    Ok(())
}

/// Open SQLite through an already authenticated regular-file descriptor.
/// Keep the transaction setup in lockstep with `open_read_only` so
/// descriptor-backed inspection has the same bounded, read-only semantics.
/// The proc descriptor is followed by an exact VFS-main-descriptor fence.
#[cfg(target_os = "linux")]
fn open_read_only_pinned(file: &PinnedSnapshotFile) -> Result<Connection, RecoveryError> {
    use std::os::fd::AsRawFd as _;

    let metadata = file
        .file
        .metadata()
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > SNAPSHOT_DATABASE_MAX_BYTES {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", file.file.as_raw_fd()));
    #[cfg(test)]
    let descriptor_path = pinned_sqlite_open_path_for_test(descriptor_path);
    let conn = Connection::open_with_flags(
        descriptor_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    #[cfg(test)]
    run_pinned_sqlite_after_open_hook();
    // SQLite resolves `/proc/self/fd/N` through xFullPathname before xOpen.
    // The resulting VFS file may therefore differ from this pin even when a
    // later pathname fence again names the pin.  Reject before timeout setup,
    // extent measurement, or any semantic SQL operation.
    verify_sqlite_main_file_binding(&file.file, &conn)?;
    conn.busy_timeout(SQLITE_BUSY_TIMEOUT)
        .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    #[cfg(test)]
    record_pinned_sqlite_semantic_open_for_test();
    consensus::snapshot_database_extent_sync(&conn)
        .map_err(|_| RecoveryError::WorkLimitExceeded)?;
    conn.execute_batch(
        "PRAGMA query_only = ON; PRAGMA trusted_schema = OFF; BEGIN DEFERRED TRANSACTION;",
    )
    .map_err(|_| RecoveryError::DatabaseUnavailable)?;
    Ok(conn)
}

#[cfg(not(target_os = "linux"))]
fn open_read_only_pinned(_file: &PinnedSnapshotFile) -> Result<Connection, RecoveryError> {
    Err(RecoveryError::BackupCorrupt)
}

/// Open a writable SQLite connection through a previously authenticated
/// descriptor.  Staging uses this after its destination pin has been
/// acquired, so the inspection and recovery-pending mutation are performed
/// on the very inode that was copied from the checkpoint.
#[cfg(target_os = "linux")]
fn open_read_write_pinned(file: &PinnedSnapshotFile) -> Result<Connection, RecoveryError> {
    use std::os::fd::AsRawFd as _;

    let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", file.file.as_raw_fd()));
    let conn = Connection::open_with_flags(
        descriptor_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| RecoveryError::FileOperationFailed)?;
    verify_sqlite_main_file_binding(&file.file, &conn)?;
    conn.busy_timeout(SQLITE_BUSY_TIMEOUT)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    consensus::install_snapshot_database_extent_guard_sync(&conn)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    Ok(conn)
}

#[cfg(not(target_os = "linux"))]
fn open_read_write_pinned(_file: &PinnedSnapshotFile) -> Result<Connection, RecoveryError> {
    Err(RecoveryError::FileOperationFailed)
}

fn validate_database_snapshot(
    conn: &Connection,
    budget: &InspectionBudget,
) -> Result<(), RecoveryError> {
    budget.check()?;
    let result: String = conn
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|error| inspection_sql_error(error, budget))?;
    budget.check()?;
    if result != "ok" {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok(())
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool, RecoveryError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )
    .map_err(|_| RecoveryError::CorruptReplica)
}

fn sqlite_backup_from_pinned(
    source: &PinnedSnapshotFile,
    destination: &Path,
    max: u64,
) -> Result<PinnedSnapshotFile, RecoveryError> {
    let source_metadata = source
        .file
        .metadata()
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    if source_metadata.len() == 0 || source_metadata.len() > max {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    let source = open_read_only_pinned(source)?;
    let destination_creator = private_create_new(destination)?;
    let destination_file =
        PinnedSnapshotFile::open(destination).map_err(|_| RecoveryError::FileOperationFailed)?;
    destination_file
        .verify_writer_identity(&destination_creator)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    let mut destination_conn = open_read_write_created(&destination_creator)?;
    {
        let backup = Backup::new(&source, &mut destination_conn)
            .map_err(|_| RecoveryError::FileOperationFailed)?;
        backup
            .run_to_completion(128, Duration::ZERO, None)
            .map_err(|_| RecoveryError::FileOperationFailed)?;
    }
    destination_conn
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode = DELETE;")
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    drop(destination_conn);
    destination_file
        .verify_writer_identity(&destination_creator)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    destination_file
        .verify_path_identity(destination)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    destination_file
        .file
        .sync_all()
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    let metadata = destination_file
        .file
        .metadata()
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    if metadata.len() == 0 || metadata.len() > max {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    Ok(destination_file)
}

/// Open an SQLite writer through the inode created by `private_create_new`.
/// The proc descriptor is intentionally used instead of the destination
/// pathname so a rename cannot redirect a staged/backup writer after its
/// destination pin has been published.
#[cfg(target_os = "linux")]
fn open_read_write_created(writer: &File) -> Result<Connection, RecoveryError> {
    use std::os::fd::AsRawFd as _;

    let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", writer.as_raw_fd()));
    let destination_conn = Connection::open_with_flags(
        descriptor_path,
        // `/proc/self/fd/N` is a trusted duplicate of `writer`; applying
        // SQLite's pathname `NOFOLLOW` flag here would reject that procfs
        // descriptor symlink before SQLite reaches the held inode.
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| RecoveryError::FileOperationFailed)?;
    verify_sqlite_main_file_binding(writer, &destination_conn)?;
    consensus::install_snapshot_database_extent_guard_sync(&destination_conn)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    Ok(destination_conn)
}

#[cfg(not(target_os = "linux"))]
fn open_read_write_created(_writer: &File) -> Result<Connection, RecoveryError> {
    Err(RecoveryError::FileOperationFailed)
}

fn copy_file_bounded_from(
    source_file: &mut File,
    destination: &Path,
    max: u64,
) -> Result<PinnedSnapshotFile, RecoveryError> {
    use std::io::{Seek, SeekFrom};

    let source_metadata = source_file
        .metadata()
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    if !source_metadata.is_file() || source_metadata.len() == 0 || source_metadata.len() > max {
        return Err(RecoveryError::WorkLimitExceeded);
    }
    source_file
        .seek(SeekFrom::Start(0))
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    let mut destination_file = private_create_new(destination)?;
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut copied = 0_u64;
    loop {
        let read = source_file
            .read(&mut buffer)
            .map_err(|_| RecoveryError::FileOperationFailed)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(u64::try_from(read).map_err(|_| RecoveryError::WorkLimitExceeded)?)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if copied > max {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        destination_file
            .write_all(&buffer[..read])
            .map_err(|_| RecoveryError::FileOperationFailed)?;
    }
    if copied != source_metadata.len() {
        return Err(RecoveryError::SourceChanged);
    }
    destination_file
        .flush()
        .and_then(|_| destination_file.sync_all())
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    // Pin the exact inode before releasing its only writer.  Unlike a
    // pathname reopen, this preserves source-to-destination authority across
    // the temporary database's SQLite preparation and atomic promotion.
    let destination_pin =
        PinnedSnapshotFile::open(destination).map_err(|_| RecoveryError::FileOperationFailed)?;
    destination_pin
        .verify_writer_identity(&destination_file)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    destination_pin
        .verify_path_identity(destination)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    drop(destination_file);
    Ok(destination_pin)
}

fn hash_reader(
    reader: &mut impl Read,
    hasher: &mut Sha256,
    max: u64,
    budget: Option<&InspectionBudget>,
) -> Result<u64, RecoveryError> {
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        if let Some(budget) = budget {
            budget.check()?;
        }
        let read = reader
            .read(&mut buffer)
            .map_err(|_| RecoveryError::BackupCorrupt)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| RecoveryError::WorkLimitExceeded)?)
            .ok_or(RecoveryError::WorkLimitExceeded)?;
        if total > max {
            return Err(RecoveryError::WorkLimitExceeded);
        }
        hasher.update(&buffer[..read]);
    }
    Ok(total)
}

fn validate_snapshot_name(name: &str) -> Result<(), RecoveryError> {
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.chars().any(char::is_control)
    {
        return Err(RecoveryError::CorruptReplica);
    }
    Ok(())
}

fn feed_json<T: Serialize>(hasher: &mut Sha256, value: &T) -> Result<(), RecoveryError> {
    let encoded = serde_json::to_vec(value).map_err(|_| RecoveryError::CorruptReplica)?;
    hasher.update(
        u64::try_from(encoded.len())
            .map_err(|_| RecoveryError::WorkLimitExceeded)?
            .to_be_bytes(),
    );
    hasher.update(encoded);
    Ok(())
}

fn verify_mac(
    key: &RecoveryIntegrityKey,
    domain: &[u8],
    parts: &[&[u8]],
    observed: RecoveryDigest,
) -> Result<(), RecoveryError> {
    let mut verifier = hmac::Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    verifier.update(domain);
    for part in parts {
        verifier.update(
            &u64::try_from(part.len())
                .map_err(|_| RecoveryError::BackupCorrupt)?
                .to_be_bytes(),
        );
        verifier.update(part);
    }
    verifier
        .verify_slice(&observed.as_bytes())
        .map_err(|_| RecoveryError::BackupCorrupt)
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), RecoveryError> {
    let parent = path.parent().ok_or(RecoveryError::FileOperationFailed)?;
    let temporary = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or(RecoveryError::FileOperationFailed)?
    ));
    remove_regular_file_if_present(&temporary)?;
    let encoded = serde_json::to_vec(value).map_err(|_| RecoveryError::FileOperationFailed)?;
    let mut file = private_create_new(&temporary)?;
    file.write_all(&encoded)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    // Keep both the creating writer and an exact read pin live across rename
    // and the directory fsync.  A byte-identical replacement of `.tmp` must
    // never become the authenticated workflow or manifest merely because it
    // was present when a later pathname was reopened.
    let temporary_pin =
        PinnedSnapshotFile::open(&temporary).map_err(|_| RecoveryError::FileOperationFailed)?;
    temporary_pin
        .verify_writer_identity(&file)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    temporary_pin
        .verify_path_identity(&temporary)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    #[cfg(test)]
    run_atomic_write_boundary_hook(AtomicWriteTestBoundary::BeforeRename, &temporary);
    temporary_pin
        .verify_writer_identity(&file)
        .and_then(|_| temporary_pin.verify_path_identity(&temporary))
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    fs::rename(&temporary, path).map_err(|_| RecoveryError::FileOperationFailed)?;
    #[cfg(test)]
    run_atomic_write_boundary_hook(AtomicWriteTestBoundary::AfterRename, path);
    sync_directory(parent)?;
    #[cfg(test)]
    run_atomic_write_boundary_hook(AtomicWriteTestBoundary::AfterDirectorySync, path);
    temporary_pin
        .verify_writer_identity(&file)
        .map_err(|_| RecoveryError::FileOperationFailed)?;
    temporary_pin
        .verify_path_identity(path)
        .map_err(|_| RecoveryError::FileOperationFailed)
}

fn read_bounded_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    max: u64,
) -> Result<T, RecoveryError> {
    let mut file = open_regular_read(path).map_err(|_| RecoveryError::BackupCorrupt)?;
    let metadata = file.metadata().map_err(|_| RecoveryError::BackupCorrupt)?;
    validate_private_file_metadata(&metadata)?;
    if metadata.len() == 0 || metadata.len() > max {
        return Err(RecoveryError::BackupCorrupt);
    }
    #[cfg(test)]
    run_bounded_json_after_open_hook(path);
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| RecoveryError::BackupCorrupt)?,
    );
    let bounded = max.checked_add(1).ok_or(RecoveryError::BackupCorrupt)?;
    Read::by_ref(&mut file)
        .take(bounded)
        .read_to_end(&mut bytes)
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    let byte_length = u64::try_from(bytes.len()).map_err(|_| RecoveryError::BackupCorrupt)?;
    let post_metadata = file.metadata().map_err(|_| RecoveryError::BackupCorrupt)?;
    validate_private_file_metadata(&post_metadata)?;
    if byte_length != metadata.len() || post_metadata.len() != metadata.len() || byte_length > max {
        return Err(RecoveryError::BackupCorrupt);
    }
    let observed = open_regular_read(path).map_err(|_| RecoveryError::BackupCorrupt)?;
    let observed_metadata = observed
        .metadata()
        .map_err(|_| RecoveryError::BackupCorrupt)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if observed_metadata.dev() != metadata.dev() || observed_metadata.ino() != metadata.ino() {
            return Err(RecoveryError::BackupCorrupt);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = observed_metadata;
        return Err(RecoveryError::InvalidRequest);
    }
    serde_json::from_slice(&bytes).map_err(|_| RecoveryError::BackupCorrupt)
}

fn remove_regular_file_if_present(path: &Path) -> Result<(), RecoveryError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(RecoveryError::FileOperationFailed);
            }
            fs::remove_file(path).map_err(|_| RecoveryError::FileOperationFailed)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(RecoveryError::FileOperationFailed),
    }
}

fn require_path_absent(path: &Path) -> Result<(), RecoveryError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(RecoveryError::FileOperationFailed),
    }
}

fn sync_directory(path: &Path) -> Result<(), RecoveryError> {
    open_directory(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| RecoveryError::FileOperationFailed)
}

fn open_regular_read(path: &Path) -> std::io::Result<File> {
    open_regular_read_nofollow(path)
}

fn open_directory(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY);
    }
    options.open(path)
}

#[cfg(test)]
mod fixed_snapshot_copy_tests {
    use super::*;

    fn snapshot_envelope(payload: &[u8]) -> Vec<u8> {
        let digest: [u8; 32] = Sha256::digest(payload).into();
        let mut bytes = payload.to_vec();
        bytes.extend_from_slice(SNAPSHOT_FOOTER_MAGIC);
        bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&digest);
        bytes
    }

    fn fs_verity_snapshot_tempdir(prefix: &str) -> tempfile::TempDir {
        const QUALIFICATION_ENV: &str = "OPC_FS_VERITY_QUALIFICATION";
        const SNAPSHOT_ROOT_ENV: &str = "OPC_FS_VERITY_SNAPSHOT_ROOT";

        let qualification_required = std::env::var_os(QUALIFICATION_ENV).as_deref()
            == Some(std::ffi::OsStr::new("required"));
        match std::env::var_os(SNAPSHOT_ROOT_ENV) {
            Some(root) => {
                let root = PathBuf::from(root);
                assert!(
                    root.is_absolute(),
                    "{SNAPSHOT_ROOT_ENV} must be an absolute fs-verity snapshot root"
                );
                tempfile::Builder::new()
                    .prefix(prefix)
                    .tempdir_in(root)
                    .expect("create fs-verity snapshot fixture directory")
            }
            None if qualification_required => {
                panic!("required fs-verity qualification requires {SNAPSHOT_ROOT_ENV}")
            }
            None => tempfile::Builder::new()
                .prefix(prefix)
                .tempdir()
                .expect("create local snapshot fixture directory"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn regular_reader_rejects_a_fifo_without_waiting_for_a_writer() {
        use nix::sys::stat::Mode;

        let directory = tempfile::tempdir().expect("FIFO recovery directory");
        let fifo = directory.path().join("recovery.fifo");
        nix::unistd::mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).expect("create recovery FIFO");
        let started = Instant::now();
        assert!(open_regular_read(&fifo).is_err());
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "FIFO rejection must not wait for a writer"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn regular_reader_rejects_a_character_device_before_any_read_open() {
        crate::sqlite::reset_regular_read_open_attempts_for_test();
        assert!(open_regular_read(Path::new("/dev/null")).is_err());
        assert_eq!(
            crate::sqlite::regular_read_open_attempts_for_test(),
            0,
            "a non-regular device must be rejected by the O_PATH fstat gate"
        );
    }

    #[test]
    fn atomic_json_write_rejects_identical_inode_replacement_at_each_promotion_boundary() {
        for (boundary, label, preserves_prior) in [
            (AtomicWriteTestBoundary::BeforeRename, "temporary", true),
            (AtomicWriteTestBoundary::AfterRename, "promoted", false),
            (
                AtomicWriteTestBoundary::AfterDirectorySync,
                "post-directory-sync",
                false,
            ),
        ] {
            let directory = tempfile::tempdir().expect("atomic JSON directory");
            let destination = directory.path().join("workflow.json");
            std::fs::write(&destination, b"{\"old\":true}").expect("write prior workflow");
            install_atomic_write_boundary_hook(boundary, move |path| {
                let clone = std::fs::read(path).expect("read byte-identical attacker clone");
                std::fs::remove_file(path).expect("unlink authenticated inode");
                std::fs::write(path, clone).expect("publish byte-identical replacement");
            });

            assert_eq!(
                atomic_write_json(&destination, &serde_json::json!({"next": true})),
                Err(RecoveryError::FileOperationFailed),
                "the {} promotion boundary must retain creator inode authority",
                label,
            );
            if preserves_prior {
                assert_eq!(
                    std::fs::read(&destination).expect("read prior workflow"),
                    b"{\"old\":true}",
                    "failed temporary promotion must preserve the old workflow"
                );
            }
        }
    }

    #[test]
    fn snapshot_and_database_promotions_retain_the_temp_inode_through_directory_sync() {
        for role in ["snapshot", "database"] {
            for (boundary, label, preserves_prior) in [
                (PromotionTestBoundary::BeforeRename, "before rename", true),
                (PromotionTestBoundary::AfterRename, "after rename", false),
                (
                    PromotionTestBoundary::AfterDirectorySync,
                    "after directory sync",
                    false,
                ),
            ] {
                let directory = tempfile::tempdir().expect("promotion directory");
                let temporary = directory.path().join(format!("{role}.part"));
                let promoted = directory.path().join(format!("{role}.live"));
                std::fs::write(&temporary, b"pinned promotion payload")
                    .expect("write temporary inode");
                std::fs::write(&promoted, b"prior destination").expect("write prior destination");
                let pin = PinnedSnapshotFile::open(&temporary).expect("pin temporary inode");
                let prior = PinnedSnapshotFile::open(&promoted).expect("pin prior destination");
                install_promotion_boundary_hook(boundary, move |path| {
                    let clone = std::fs::read(path).expect("read byte-identical replacement");
                    std::fs::remove_file(path).expect("unlink authenticated inode");
                    std::fs::write(path, clone).expect("publish byte-identical replacement");
                });

                assert!(
                    matches!(
                        promote_pinned_file(
                            pin,
                            &temporary,
                            &promoted,
                            directory.path(),
                            PromotionDestination::Present(&prior),
                        ),
                        Err(RecoveryError::FileOperationFailed)
                    ),
                    "{role} {label} replacement must fail closed"
                );
                if preserves_prior {
                    assert_eq!(
                        std::fs::read(&promoted).expect("read prior destination"),
                        b"prior destination",
                        "{role} pre-rename failure must retain the previous destination"
                    );
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn promotion_exchanges_only_the_pinned_existing_destination() {
        let directory = tempfile::tempdir().expect("promotion directory");
        let temporary = directory.path().join("target.part");
        let promoted = directory.path().join("target.sqlite");
        std::fs::write(&temporary, b"recovered target").expect("write temporary target");
        std::fs::write(&promoted, b"original target").expect("write original target");
        let replacement = directory.path().join("replacement.sqlite");
        std::fs::write(&replacement, b"original target").expect("write replacement target");
        let new = PinnedSnapshotFile::open(&temporary).expect("pin prepared target");
        let old = PinnedSnapshotFile::open(&promoted).expect("pin original target");
        let replacement_for_hook = replacement.clone();
        install_promotion_boundary_hook(
            PromotionTestBoundary::BeforeDestinationRename,
            move |path| {
                std::fs::rename(&replacement_for_hook, path)
                    .expect("replace target immediately before promotion");
            },
        );

        assert!(
            matches!(
                promote_pinned_file(
                    new,
                    &temporary,
                    &promoted,
                    directory.path(),
                    PromotionDestination::Present(&old),
                ),
                Err(RecoveryError::SourceChanged)
            ),
            "a late replacement must not be accepted as the expected target"
        );
        assert_eq!(
            std::fs::read(&promoted).expect("read restored replacement"),
            b"original target",
            "the exchange rollback must retain the foreign replacement"
        );
        assert!(
            old.verify_path_identity(&promoted).is_err(),
            "the destination must still name the replacement inode, not the held original"
        );
        assert_eq!(
            std::fs::read(&temporary).expect("read retained prepared target"),
            b"recovered target",
            "the prepared target must be restored to its temporary name on rejection"
        );
    }

    #[cfg(unix)]
    #[test]
    fn promotion_disposition_is_path_specific_and_rejects_same_byte_replacement() {
        let directory = tempfile::tempdir().expect("promotion directory");
        let temporary = directory.path().join("snapshot.part");
        let promoted = directory.path().join("snapshot-target.opc");
        let current_elsewhere = directory.path().join("snapshot-current.opc");
        let replacement = directory.path().join("replacement.opc");
        let key = RecoveryIntegrityKey::new([0x94; 32]).expect("identity key");
        std::fs::write(&temporary, b"prepared snapshot").expect("write temporary snapshot");
        std::fs::write(&promoted, b"displaced historical snapshot")
            .expect("write promoted snapshot");
        std::fs::write(&current_elsewhere, b"selected current snapshot")
            .expect("write selected snapshot elsewhere");

        let displaced = PinnedSnapshotFile::open(&promoted).expect("pin exact destination");
        let disposition =
            promotion_disposition(&key, &promoted, PromotionDestination::Present(&displaced))
                .expect("journal exact destination disposition");
        std::fs::copy(&promoted, &replacement).expect("copy byte-identical replacement");
        std::fs::rename(&replacement, &promoted).expect("replace destination inode");

        assert!(
            matches!(
                promotion_destination_from_workflow(&key, &promoted, disposition),
                Err(RecoveryError::BackupCorrupt)
            ),
            "resume must reject a byte-identical replacement of the journaled pathname, not compare another current snapshot"
        );
        assert_eq!(
            std::fs::read(&temporary).expect("prepared temporary remains"),
            b"prepared snapshot"
        );
    }

    #[cfg(unix)]
    #[test]
    fn absent_promotion_disposition_rejects_late_destination_appearance() {
        let directory = tempfile::tempdir().expect("promotion directory");
        let temporary = directory.path().join("target.part");
        let promoted = directory.path().join("target.opc");
        let key = RecoveryIntegrityKey::new([0x95; 32]).expect("identity key");
        std::fs::write(&temporary, b"prepared target").expect("write temporary target");
        let prepared = PinnedSnapshotFile::open(&temporary).expect("pin temporary target");
        let disposition = promotion_disposition(&key, &promoted, PromotionDestination::Absent)
            .expect("journal absent disposition");
        std::fs::write(&promoted, b"late destination").expect("publish late destination");

        assert!(
            matches!(
                promotion_destination_from_workflow(&key, &promoted, disposition),
                Err(RecoveryError::BackupCorrupt)
            ),
            "a retry must reject a destination which appeared after an absent journal"
        );
        assert!(
            matches!(
                promote_pinned_file(
                    prepared,
                    &temporary,
                    &promoted,
                    directory.path(),
                    PromotionDestination::Absent,
                ),
                Err(RecoveryError::SourceChanged)
            ),
            "fresh absent promotion must use RENAME_NOREPLACE"
        );
        assert_eq!(
            std::fs::read(&promoted).expect("late destination remains"),
            b"late destination"
        );
    }

    #[cfg(unix)]
    #[test]
    fn completed_present_promotion_requires_and_cleans_the_journaled_displaced_inode() {
        let directory = tempfile::tempdir().expect("promotion directory");
        let temporary = directory.path().join("target.part");
        let promoted = directory.path().join("target.sqlite");
        let key = RecoveryIntegrityKey::new([0x96; 32]).expect("identity key");
        std::fs::write(&temporary, b"prepared target").expect("write temporary target");
        std::fs::write(&promoted, b"displaced target").expect("write promoted target");
        let prepared = PinnedSnapshotFile::open(&temporary).expect("pin temporary target");
        let displaced = PinnedSnapshotFile::open(&promoted).expect("pin displaced target");
        let disposition =
            promotion_disposition(&key, &promoted, PromotionDestination::Present(&displaced))
                .expect("journal present disposition");

        let promoted_file = promote_pinned_file(
            prepared,
            &temporary,
            &promoted,
            directory.path(),
            PromotionDestination::Present(&displaced),
        )
        .expect("exchange prepared and displaced inodes");
        let expected_identity = pinned_file_identity(&key, &promoted_file)
            .expect("record prepared identity for workflow");
        drop(promoted_file);

        let completed = open_completed_promotion_from_workflow(
            &key,
            &temporary,
            &promoted,
            directory.path(),
            expected_identity,
            disposition,
        )
        .expect("validate completed exchange")
        .expect("completed exchange is recognized");
        completed
            .verify_path_identity(&promoted)
            .expect("public path keeps prepared inode");
        reconcile_completed_promotion_cleanup(
            &key,
            &temporary,
            &promoted,
            directory.path(),
            expected_identity,
            disposition,
            &completed,
        )
        .expect("cleanup removes only the journaled displaced inode");
        assert!(
            !temporary.exists(),
            "completed Present promotion must not retain the displaced inode"
        );
    }

    #[cfg(unix)]
    #[test]
    fn completed_absent_promotion_requires_public_prepared_inode_and_no_temporary() {
        let directory = tempfile::tempdir().expect("promotion directory");
        let temporary = directory.path().join("target.part");
        let promoted = directory.path().join("target.sqlite");
        let key = RecoveryIntegrityKey::new([0x97; 32]).expect("identity key");
        std::fs::write(&temporary, b"prepared target").expect("write temporary target");
        let prepared = PinnedSnapshotFile::open(&temporary).expect("pin temporary target");
        let disposition = promotion_disposition(&key, &promoted, PromotionDestination::Absent)
            .expect("journal absent disposition");
        let promoted_file = promote_pinned_file(
            prepared,
            &temporary,
            &promoted,
            directory.path(),
            PromotionDestination::Absent,
        )
        .expect("rename prepared inode into absent destination");
        let expected_identity = pinned_file_identity(&key, &promoted_file)
            .expect("record prepared identity for workflow");
        drop(promoted_file);

        let completed = open_completed_promotion_from_workflow(
            &key,
            &temporary,
            &promoted,
            directory.path(),
            expected_identity,
            disposition,
        )
        .expect("validate completed absent promotion")
        .expect("completed absent promotion is recognized");
        completed
            .verify_path_identity(&promoted)
            .expect("public path keeps prepared inode");
        assert!(
            !temporary.exists(),
            "completed absent promotion must leave no temporary pathname"
        );
    }

    #[cfg(unix)]
    #[test]
    fn present_promotion_cleanup_is_idempotent_for_fresh_and_resume_snapshot_and_database() {
        for role in ["snapshot", "database"] {
            for completion in ["fresh", "resume"] {
                let directory = tempfile::tempdir().expect("promotion directory");
                let temporary = directory.path().join(format!("{role}.part"));
                let promoted = directory.path().join(format!("{role}.live"));
                let key = RecoveryIntegrityKey::new([0xa3; 32]).expect("identity key");
                std::fs::write(&temporary, b"prepared target").expect("write prepared target");
                std::fs::write(&promoted, b"displaced target").expect("write displaced target");
                let prepared = PinnedSnapshotFile::open(&temporary).expect("pin prepared target");
                let displaced = PinnedSnapshotFile::open(&promoted).expect("pin displaced target");
                let disposition = promotion_disposition(
                    &key,
                    &promoted,
                    PromotionDestination::Present(&displaced),
                )
                .expect("journal present destination");
                let expected_identity =
                    pinned_file_identity(&key, &prepared).expect("journal prepared identity");
                let installed = promote_pinned_file(
                    prepared,
                    &temporary,
                    &promoted,
                    directory.path(),
                    PromotionDestination::Present(&displaced),
                )
                .expect("exchange prepared and displaced inodes");
                let installed = if completion == "fresh" {
                    installed
                } else {
                    drop(installed);
                    open_completed_promotion_from_workflow(
                        &key,
                        &temporary,
                        &promoted,
                        directory.path(),
                        expected_identity,
                        disposition,
                    )
                    .expect("resume recognizes completed exchange")
                    .expect("completed exchange is public")
                };

                reconcile_completed_promotion_cleanup(
                    &key,
                    &temporary,
                    &promoted,
                    directory.path(),
                    expected_identity,
                    disposition,
                    &installed,
                )
                .expect("cleanup removes the exact displaced inode");
                assert!(
                    !temporary.exists(),
                    "{role} {completion} completion must leave no promotion residue"
                );
                // This models a crash after unlink, before parent fsync or
                // workflow publication: the journal remains authoritative
                // and a retry only re-proves and syncs the completed cleanup.
                reconcile_completed_promotion_cleanup(
                    &key,
                    &temporary,
                    &promoted,
                    directory.path(),
                    expected_identity,
                    disposition,
                    &installed,
                )
                .expect("already-unlinked cleanup is an idempotent replay");
                installed
                    .verify_path_identity(&promoted)
                    .expect("replay retains the installed inode");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn present_promotion_cleanup_rejects_same_byte_public_or_temporary_replacements() {
        for replacement in ["public", "temporary"] {
            let directory = tempfile::tempdir().expect("promotion directory");
            let temporary = directory.path().join("target.part");
            let promoted = directory.path().join("target.sqlite");
            let replacement_path = directory.path().join("replacement.sqlite");
            let key = RecoveryIntegrityKey::new([0xa4; 32]).expect("identity key");
            std::fs::write(&temporary, b"prepared target").expect("write prepared target");
            std::fs::write(&promoted, b"displaced target").expect("write displaced target");
            let prepared = PinnedSnapshotFile::open(&temporary).expect("pin prepared target");
            let displaced = PinnedSnapshotFile::open(&promoted).expect("pin displaced target");
            let disposition =
                promotion_disposition(&key, &promoted, PromotionDestination::Present(&displaced))
                    .expect("journal present destination");
            let expected_identity =
                pinned_file_identity(&key, &prepared).expect("journal prepared identity");
            let installed = promote_pinned_file(
                prepared,
                &temporary,
                &promoted,
                directory.path(),
                PromotionDestination::Present(&displaced),
            )
            .expect("exchange prepared and displaced inodes");
            let replaced = if replacement == "public" {
                &promoted
            } else {
                &temporary
            };
            std::fs::copy(replaced, &replacement_path).expect("copy byte-identical replacement");
            std::fs::rename(&replacement_path, replaced).expect("replace journaled pathname");

            assert_eq!(
                reconcile_completed_promotion_cleanup(
                    &key,
                    &temporary,
                    &promoted,
                    directory.path(),
                    expected_identity,
                    disposition,
                    &installed,
                ),
                Err(RecoveryError::BackupCorrupt),
                "a same-byte {replacement} replacement must fail closed"
            );
            assert!(
                replaced.exists(),
                "cleanup must preserve the foreign {replacement} replacement"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn present_promotion_cleanup_preserves_a_nonregular_temporary_entry() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("promotion directory");
        let temporary = directory.path().join("target.part");
        let promoted = directory.path().join("target.sqlite");
        let foreign = directory.path().join("foreign-target");
        let key = RecoveryIntegrityKey::new([0xa6; 32]).expect("identity key");
        std::fs::write(&temporary, b"prepared target").expect("write prepared target");
        std::fs::write(&promoted, b"displaced target").expect("write displaced target");
        let prepared = PinnedSnapshotFile::open(&temporary).expect("pin prepared target");
        let displaced = PinnedSnapshotFile::open(&promoted).expect("pin displaced target");
        let disposition =
            promotion_disposition(&key, &promoted, PromotionDestination::Present(&displaced))
                .expect("journal present destination");
        let expected_identity =
            pinned_file_identity(&key, &prepared).expect("journal prepared identity");
        let installed = promote_pinned_file(
            prepared,
            &temporary,
            &promoted,
            directory.path(),
            PromotionDestination::Present(&displaced),
        )
        .expect("exchange prepared and displaced inodes");
        std::fs::write(&foreign, b"foreign entry").expect("write foreign target");
        std::fs::remove_file(&temporary).expect("remove journaled displaced test fixture");
        symlink(&foreign, &temporary).expect("replace temporary with symlink");

        assert_eq!(
            reconcile_completed_promotion_cleanup(
                &key,
                &temporary,
                &promoted,
                directory.path(),
                expected_identity,
                disposition,
                &installed,
            ),
            Err(RecoveryError::BackupCorrupt),
            "a nonregular temporary must never be treated as cleanup replay"
        );
        assert!(
            std::fs::symlink_metadata(&temporary)
                .expect("foreign temporary remains")
                .file_type()
                .is_symlink(),
            "failed cleanup must preserve the foreign entry"
        );
    }

    #[cfg(unix)]
    #[test]
    fn successive_snapshot_present_campaigns_leave_no_quarantine_residue() {
        let directory = tempfile::tempdir().expect("promotion directory");
        let file_name = "snapshot-00000000-0000-4000-8000-000000000097.opc";
        let promoted = directory.path().join(file_name);
        let key = RecoveryIntegrityKey::new([0xa5; 32]).expect("identity key");
        std::fs::write(&promoted, b"initial displaced snapshot")
            .expect("write initial destination");
        for campaign in 0_u8..40 {
            let plan = RecoveryDigest::from_bytes([campaign; 32]);
            let temporary = snapshot_promotion_temporary_path_for(
                directory.path(),
                "target-a",
                plan,
                file_name,
            )
            .expect("derive campaign temporary");
            std::fs::write(&temporary, format!("campaign {campaign} prepared"))
                .expect("write campaign temporary");
            let prepared = PinnedSnapshotFile::open(&temporary).expect("pin prepared snapshot");
            let displaced = PinnedSnapshotFile::open(&promoted).expect("pin displaced snapshot");
            let disposition =
                promotion_disposition(&key, &promoted, PromotionDestination::Present(&displaced))
                    .expect("journal present destination");
            let expected_identity =
                pinned_file_identity(&key, &prepared).expect("journal prepared identity");
            let installed = promote_pinned_file(
                prepared,
                &temporary,
                &promoted,
                directory.path(),
                PromotionDestination::Present(&displaced),
            )
            .expect("campaign exchange");
            reconcile_completed_promotion_cleanup(
                &key,
                &temporary,
                &promoted,
                directory.path(),
                expected_identity,
                disposition,
                &installed,
            )
            .expect("campaign cleanup");
            assert!(
                !temporary.exists(),
                "campaign {campaign} must release its admission artifact"
            );
        }
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("read snapshot directory")
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().contains(".part"))
                .count(),
            0,
            "more than the 32-artifact admission limit must not leave recovery parts"
        );
    }

    #[cfg(unix)]
    #[test]
    fn successive_database_present_campaigns_leave_no_opc_recovery_residue() {
        let directory = tempfile::tempdir().expect("database directory");
        let promoted = directory.path().join("session.sqlite");
        let key = RecoveryIntegrityKey::new([0xa7; 32]).expect("identity key");
        std::fs::write(&promoted, b"initial displaced database")
            .expect("write initial destination");
        for campaign in 0_u8..40 {
            let temporary = directory
                .path()
                .join(format!(".opc-recovery-{campaign:02x}.sqlite"));
            std::fs::write(&temporary, format!("campaign {campaign} prepared"))
                .expect("write campaign temporary");
            let prepared = PinnedSnapshotFile::open(&temporary).expect("pin prepared database");
            let displaced = PinnedSnapshotFile::open(&promoted).expect("pin displaced database");
            let disposition =
                promotion_disposition(&key, &promoted, PromotionDestination::Present(&displaced))
                    .expect("journal present destination");
            let expected_identity =
                pinned_file_identity(&key, &prepared).expect("journal prepared identity");
            let installed = promote_pinned_file(
                prepared,
                &temporary,
                &promoted,
                directory.path(),
                PromotionDestination::Present(&displaced),
            )
            .expect("campaign exchange");
            reconcile_completed_promotion_cleanup(
                &key,
                &temporary,
                &promoted,
                directory.path(),
                expected_identity,
                disposition,
                &installed,
            )
            .expect("campaign cleanup");
            assert!(
                !temporary.exists(),
                "database campaign {campaign} must release its recovery temporary"
            );
        }
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("read database directory")
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".opc-recovery-"))
                .count(),
            0,
            "successful database campaigns must leave no .opc-recovery-* residue"
        );
    }

    #[cfg(unix)]
    #[test]
    fn crash_after_snapshot_exchange_resumes_with_the_journaled_displaced_inode() {
        let directory = tempfile::tempdir().expect("promotion directory");
        let temporary = directory.path().join("snapshot.part");
        let promoted = directory.path().join("snapshot.opc");
        let key = RecoveryIntegrityKey::new([0x98; 32]).expect("identity key");
        std::fs::write(&temporary, b"prepared snapshot").expect("write temporary snapshot");
        std::fs::write(&promoted, b"displaced snapshot").expect("write destination snapshot");
        let prepared = PinnedSnapshotFile::open(&temporary).expect("pin temporary snapshot");
        let displaced = PinnedSnapshotFile::open(&promoted).expect("pin destination snapshot");
        let disposition =
            promotion_disposition(&key, &promoted, PromotionDestination::Present(&displaced))
                .expect("journal destination disposition");
        let expected_identity =
            pinned_file_identity(&key, &prepared).expect("journal temporary identity");

        fail_next_promotion_after_rename();
        assert!(matches!(
            promote_pinned_file(
                prepared,
                &temporary,
                &promoted,
                directory.path(),
                PromotionDestination::Present(&displaced),
            ),
            Err(RecoveryError::InjectedFailure)
        ));
        let resumed = open_completed_promotion_from_workflow(
            &key,
            &temporary,
            &promoted,
            directory.path(),
            expected_identity,
            disposition,
        )
        .expect("resume validates completed exchange")
        .expect("completed exchange is recognized");
        resumed
            .verify_path_identity(&promoted)
            .expect("prepared inode remains public after resume");
        assert_eq!(
            std::fs::read(&temporary).expect("read retained displaced snapshot"),
            b"displaced snapshot"
        );
    }

    #[cfg(unix)]
    fn make_private_json(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::write(path, bytes).expect("write private JSON fixture");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("make private JSON fixture");
    }

    #[cfg(unix)]
    #[test]
    fn bounded_json_read_rejects_a_same_byte_path_replacement_after_pin_acquisition() {
        let directory = tempfile::tempdir().expect("bounded JSON directory");
        let path = directory.path().join("workflow.json");
        make_private_json(&path, b"{\"value\":1}");
        install_bounded_json_after_open_hook(move |path| {
            let clone = std::fs::read(path).expect("read byte-identical JSON clone");
            std::fs::remove_file(path).expect("unlink pinned JSON");
            make_private_json(path, &clone);
        });

        assert_eq!(
            read_bounded_json::<serde_json::Value>(&path, 64),
            Err(RecoveryError::BackupCorrupt),
            "a pathname replacement after the held read pin must fail closed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_json_read_rejects_in_place_growth_after_pin_acquisition() {
        let directory = tempfile::tempdir().expect("bounded JSON directory");
        let path = directory.path().join("workflow.json");
        make_private_json(&path, b"{\"value\":1}");
        install_bounded_json_after_open_hook(move |path| {
            use std::io::Write as _;

            let mut file = OpenOptions::new()
                .append(true)
                .open(path)
                .expect("open pinned JSON for growth");
            file.write_all(&[b'x'; 128])
                .expect("grow pinned JSON beyond bound");
            file.sync_all().expect("sync grown JSON");
        });

        assert_eq!(
            read_bounded_json::<serde_json::Value>(&path, 64),
            Err(RecoveryError::BackupCorrupt),
            "the held reader must reject growth instead of allocating past its bound"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fixed_recovery_copy_is_sealed_only_after_the_writer_closes() {
        let directory = fs_verity_snapshot_tempdir("fs-verity-recovery-");
        let source = directory.path().join("source.opc");
        let fixed_destination = directory.path().join("fixed-copy.opc");
        let dynamic_destination = directory.path().join("dynamic-copy.opc");
        std::fs::write(&source, snapshot_envelope(b"fixed recovery snapshot"))
            .expect("write fixed recovery source");
        match seal_fixed_snapshot(&source) {
            Ok(()) => {}
            Err(RecoveryError::FileOperationFailed)
                if std::env::var_os("OPC_FS_VERITY_QUALIFICATION").as_deref()
                    != Some(std::ffi::OsStr::new("required")) =>
            {
                return;
            }
            Err(error) => panic!("unexpected source seal error: {error:?}"),
        }
        let mut source_file = PinnedSnapshotFile::open(&source).expect("pin fixed source");
        let _fixed_file =
            copy_snapshot_file_bounded(&mut source_file, &fixed_destination, 1024, true)
                .expect("copy and seal fixed recovery artifact");
        measure_fixed_snapshot(&fixed_destination)
            .expect("fixed recovery copy has a kernel seal before use");

        let _dynamic_file =
            copy_snapshot_file_bounded(&mut source_file, &dynamic_destination, 1024, false)
                .expect("copy dynamic recovery artifact");
        assert!(
            measure_fixed_snapshot(&dynamic_destination).is_err(),
            "dynamic recovery copy must not be described as immutable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pinned_snapshot_rejects_same_uid_path_replacement() {
        let directory = tempfile::tempdir().expect("snapshot directory");
        let path = directory.path().join("snapshot.opc");
        let replacement = directory.path().join("replacement.opc");
        std::fs::write(&path, snapshot_envelope(b"original")).expect("write original");
        let file = PinnedSnapshotFile::open(&path).expect("pin original");
        std::fs::write(&replacement, snapshot_envelope(b"replacement")).expect("write replacement");
        std::fs::rename(&replacement, &path).expect("replace snapshot as same uid");

        assert_eq!(
            file.verify_path_identity(&path),
            Err(RecoveryError::SourceChanged)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_sqlite_reader_rejects_a_vfs_main_descriptor_replaced_before_path_restoration() {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempfile::tempdir().expect("pinned SQLite directory");
        let public = directory.path().join("recovery.sqlite");
        let held_a = directory.path().join("held-a.sqlite");
        let stable_b = directory.path().join("stable-b.sqlite");
        let displaced_b = directory.path().join("displaced-b.sqlite");

        let a = Connection::open(&public).expect("create original SQLite database A");
        a.execute_batch("CREATE TABLE original_a (value INTEGER NOT NULL);")
            .expect("initialize SQLite database A");
        drop(a);
        let pinned_a = PinnedSnapshotFile::open(&public).expect("pin SQLite database A");

        let b = Connection::open(&stable_b).expect("create replacement SQLite database B");
        b.execute_batch("CREATE TABLE replacement_b (value INTEGER NOT NULL);")
            .expect("initialize SQLite database B");
        drop(b);
        assert_ne!(
            pinned_a.file.metadata().expect("stat pinned A").ino(),
            std::fs::metadata(&stable_b)
                .expect("stat replacement B")
                .ino(),
            "the causal fixture needs distinct A/B inodes"
        );

        // Model the `xFullPathname`/`xOpen` exchange: A is already pinned,
        // the public name temporarily names B, and the VFS resolves its main
        // file through B's stable link. The post-open hook restores public to
        // A before the binding check, defeating a final-path-only fence.
        std::fs::rename(&public, &held_a).expect("hold pinned pathname A");
        std::fs::hard_link(&stable_b, &public).expect("publish replacement B");
        let public_after_open = public.clone();
        let held_a_after_open = held_a.clone();
        let displaced_b_after_open = displaced_b.clone();
        install_pinned_sqlite_open_mismatch_hook(stable_b.clone(), move || {
            std::fs::rename(&public_after_open, &displaced_b_after_open)
                .expect("remove public B link after SQLite xOpen");
            std::fs::rename(&held_a_after_open, &public_after_open)
                .expect("restore public pathname A before descriptor check");
        });
        reset_pinned_sqlite_semantic_open_count_for_test();

        assert!(
            matches!(
                open_read_only_pinned(&pinned_a),
                Err(RecoveryError::SourceChanged)
            ),
            "the SQLite VFS main descriptor B must not inherit pin A's authority"
        );
        assert_eq!(
            pinned_sqlite_semantic_open_count_for_test(),
            0,
            "the VFS descriptor mismatch must reject before extent measurement or inspection"
        );
        pinned_a
            .verify_path_identity(&public)
            .expect("public pathname was restored to the original pinned A");
    }

    #[cfg(unix)]
    #[test]
    fn destination_pin_must_match_the_still_open_writer() {
        let directory = tempfile::tempdir().expect("copy directory");
        let path = directory.path().join("snapshot.part");
        let displaced = directory.path().join("displaced.part");
        let mut writer = private_create_new(&path).expect("create destination writer");
        writer
            .write_all(&snapshot_envelope(b"copied inode"))
            .expect("write destination");
        writer.flush().expect("flush destination");

        std::fs::rename(&path, &displaced).expect("displace writer inode as same uid");
        std::fs::write(&path, snapshot_envelope(b"substituted inode"))
            .expect("install pathname substitute");
        let substituted = PinnedSnapshotFile::open(&path).expect("pin pathname substitute");

        assert_eq!(
            substituted.verify_writer_identity(&writer),
            Err(RecoveryError::SourceChanged)
        );
    }

    #[cfg(unix)]
    #[test]
    fn pinned_destination_rejects_same_uid_replacement_after_promotion() {
        let directory = tempfile::tempdir().expect("promotion directory");
        let source = directory.path().join("source.opc");
        let temporary = directory.path().join("snapshot.part");
        let promoted = directory.path().join("snapshot.opc");
        let replacement = directory.path().join("replacement.opc");
        std::fs::write(&source, snapshot_envelope(b"original")).expect("write source");
        let mut source_file = PinnedSnapshotFile::open(&source).expect("pin source");
        let destination = copy_snapshot_file_bounded(&mut source_file, &temporary, 1024, false)
            .expect("copy pinned destination");
        std::fs::rename(&temporary, &promoted).expect("promote destination");
        destination
            .verify_path_identity(&promoted)
            .expect("promoted path names pinned destination");
        std::fs::write(&replacement, snapshot_envelope(b"replacement")).expect("write replacement");
        std::fs::rename(&replacement, &promoted).expect("replace promoted file as same uid");

        assert_eq!(
            destination.verify_path_identity(&promoted),
            Err(RecoveryError::SourceChanged)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn durable_file_identity_survives_a_legitimate_sqlite_mutation() {
        let directory = tempfile::tempdir().expect("database directory");
        let database = directory.path().join("recovery.sqlite");
        let key = RecoveryIntegrityKey::new([0x71; 32]).expect("identity key");
        let connection = Connection::open(&database).expect("create database");
        connection
            .execute_batch("CREATE TABLE recovery_identity_test (value INTEGER NOT NULL);")
            .expect("create test table");
        drop(connection);

        let file = PinnedSnapshotFile::open(&database).expect("pin database");
        let before = pinned_file_identity(&key, &file).expect("record installed identity");

        let connection = Connection::open(&database).expect("reopen database");
        connection
            .execute("INSERT INTO recovery_identity_test (value) VALUES (1)", [])
            .expect("apply recovery epoch mutation");
        drop(connection);

        assert_eq!(
            pinned_file_identity(&key, &file).expect("revalidate installed identity"),
            before,
            "ordinary SQLite writes must not invalidate the durable file incarnation"
        );
        file.verify_path_identity(&database)
            .expect("mutation retained pinned database inode");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn durable_file_identity_rejects_a_byte_identical_replacement() {
        let directory = tempfile::tempdir().expect("database directory");
        let database = directory.path().join("recovery.sqlite");
        let replacement = directory.path().join("replacement.sqlite");
        let key = RecoveryIntegrityKey::new([0x72; 32]).expect("identity key");
        let bytes = b"byte-identical dynamic recovery database";
        std::fs::write(&database, bytes).expect("write original database");
        let original = PinnedSnapshotFile::open(&database).expect("pin original database");
        let original_identity =
            pinned_file_identity(&key, &original).expect("record original identity");

        std::fs::write(&replacement, bytes).expect("write byte-identical replacement");
        std::fs::rename(&replacement, &database).expect("replace database as same uid");
        let substituted = PinnedSnapshotFile::open(&database).expect("pin replacement database");

        assert_ne!(
            pinned_file_identity(&key, &substituted).expect("record replacement identity"),
            original_identity,
            "a byte-identical replacement must not satisfy a persisted incarnation commitment"
        );
        assert_eq!(
            original.verify_path_identity(&database),
            Err(RecoveryError::SourceChanged),
            "the original held descriptor must not be confused with its replacement"
        );
    }

    #[test]
    fn snapshot_seal_policy_requires_an_authenticated_staged_profile() {
        let directory = tempfile::tempdir().expect("profile directory");
        let staged = directory.path().join("staged.sqlite");
        let old_target = directory.path().join("target.sqlite");
        for (path, profile, policy) in [(&staged, 2_i64, Some(1_i64)), (&old_target, 1_i64, None)] {
            let conn = Connection::open(path).expect("create profile database");
            conn.execute_batch(
                "CREATE TABLE consensus_identity (singleton INTEGER PRIMARY KEY, authority_profile INTEGER, fixed_placement_policy INTEGER);",
            )
            .expect("create profile table");
            conn.execute(
                "INSERT INTO consensus_identity (singleton, authority_profile, fixed_placement_policy) VALUES (1, ?1, ?2)",
                rusqlite::params![profile, policy],
            )
            .expect("insert profile");
        }
        assert!(snapshot_seal_policy(&staged).expect("read staged fixed profile"));
        assert!(!snapshot_seal_policy(&old_target).expect("read old target dynamic profile"));
    }

    #[test]
    fn snapshot_seal_policy_rejects_legacy_or_ambiguous_profiles() {
        let directory = tempfile::tempdir().expect("legacy profile directory");
        let legacy = directory.path().join("legacy.sqlite");
        let ambiguous = directory.path().join("ambiguous.sqlite");
        let legacy_conn = Connection::open(&legacy).expect("create legacy database");
        legacy_conn
            .execute_batch("CREATE TABLE consensus_identity (singleton INTEGER PRIMARY KEY);")
            .expect("create legacy profile table");
        let ambiguous_conn = Connection::open(&ambiguous).expect("create ambiguous database");
        ambiguous_conn
            .execute_batch(
                "CREATE TABLE consensus_identity (singleton INTEGER PRIMARY KEY, authority_profile INTEGER); \
                 INSERT INTO consensus_identity (singleton, authority_profile) VALUES (1, NULL);",
            )
            .expect("create ambiguous profile database");

        assert_eq!(
            snapshot_seal_policy(&legacy),
            Err(RecoveryError::CorruptReplica)
        );
        assert_eq!(
            snapshot_seal_policy(&ambiguous),
            Err(RecoveryError::CorruptReplica)
        );
    }
}

#[cfg(test)]
mod terminal_history_digest_tests {
    use super::*;

    fn current_checkpoint_digest(conn: &Connection) -> [u8; 32] {
        let mut budget = InspectionBudget::new(RecoveryLimits::default());
        let mut hasher = Sha256::new();
        hash_current_checkpoint(
            conn,
            &mut budget,
            &mut hasher,
            RecoveryDigest::from_bytes([0_u8; 32]),
        )
        .expect("hash current checkpoint");
        hasher.finalize().into()
    }

    #[test]
    fn offline_recovery_rejects_a_truncated_closed_v2_epoch() {
        let conn = crate::sqlite::SqliteSessionBackend::canonical_schema_connection()
            .expect("canonical database");
        conn.execute_batch(
            r#"
CREATE TABLE consensus_fenced_transition_v2_history (
    singleton INTEGER PRIMARY KEY,
    storage_configuration_epoch INTEGER NOT NULL,
    profile_digest BLOB NOT NULL,
    active_epoch INTEGER NOT NULL,
    retired_through_epoch INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    current_bound_count INTEGER NOT NULL,
    reclaim_epoch INTEGER,
    reclaim_cursor_ordinal INTEGER,
    reclaim_remaining INTEGER,
    reclaimed_entries INTEGER NOT NULL
);
CREATE TABLE consensus_fenced_transition_v2_activation (singleton INTEGER PRIMARY KEY);
CREATE TABLE consensus_fenced_transition_v2_receipts (
    request_id BLOB NOT NULL,
    history_epoch INTEGER NOT NULL,
    ordinal INTEGER NOT NULL,
    configuration_epoch INTEGER NOT NULL,
    payload_digest BLOB NOT NULL,
    retained_until TEXT NOT NULL,
    binding_digest BLOB NOT NULL,
    response_json BLOB,
    response_digest BLOB
);
"#,
        )
        .expect("install V2 recovery fixture");
        let identity = SessionConsensusIdentity::new(
            crate::consensus::SessionConsensusClusterId::from_bytes([0x71; 32]),
            SessionConsensusConfigurationId::from_bytes([0x72; 32]),
            SessionConsensusConfigurationEpoch::new(1).expect("configuration epoch"),
        );
        conn.execute(
            "INSERT INTO consensus_fenced_transition_v2_history VALUES (1, 1, ?1, 2, 0, 0, 0, NULL, NULL, NULL, 0)",
            [crate::fenced_transition::fenced_transition_v2_profile_digest().as_slice()],
        )
        .expect("insert truncated closed epoch");
        let mut request_id = [0_u8; FENCED_TRANSITION_V2_REQUEST_ID_BYTES];
        request_id[..8].copy_from_slice(&1_u64.to_be_bytes());
        request_id[48..].copy_from_slice(&1_u64.to_be_bytes());
        let retained_until = "2026-08-17T00:00:00.000000000Z";
        let payload_digest =
            consensus::fenced_transition_v2_payload_digest_for_request_id(identity, request_id)
                .expect("payload digest");
        let binding_digest = consensus::fenced_transition_v2_receipt_binding_digest(
            identity,
            request_id,
            1,
            1,
            payload_digest,
            retained_until,
        )
        .expect("binding digest");
        conn.execute(
            "INSERT INTO consensus_fenced_transition_v2_receipts VALUES (?1, 1, 1, 1, ?2, ?3, ?4, NULL, NULL)",
            rusqlite::params![
                request_id.as_slice(),
                payload_digest.as_slice(),
                retained_until,
                binding_digest.as_slice(),
            ],
        )
        .expect("insert truncated receipt");

        assert!(matches!(
            validate_fenced_transition_v2_recovery_state(&conn, identity),
            Err(RecoveryError::CorruptReplica)
        ));
    }

    #[test]
    fn terminal_history_changes_the_recovery_branch_digest() {
        let missing_history = crate::sqlite::SqliteSessionBackend::canonical_schema_connection()
            .expect("canonical database");
        let without_history = crate::sqlite::SqliteSessionBackend::canonical_schema_connection()
            .expect("canonical database");
        let with_history = crate::sqlite::SqliteSessionBackend::canonical_schema_connection()
            .expect("canonical database");
        for conn in [&missing_history, &without_history, &with_history] {
            consensus::install_recovery_validation_schema_sync(conn, false)
                .expect("install consensus schema");
            conn.execute(
                "INSERT INTO consensus_identity (singleton, schema_version, cluster_id, configuration_id, configuration_epoch) VALUES (1, ?1, ?2, ?3, 1)",
                rusqlite::params![
                    i64::from(SESSION_CONSENSUS_SCHEMA_VERSION),
                    [0x31_u8; 32].as_slice(),
                    [0x32_u8; 32].as_slice(),
                ],
            )
            .expect("insert storage identity");
        }
        missing_history
            .execute_batch("DROP TABLE consensus_membership_terminal_history")
            .expect("remove optional terminal history table");
        with_history
            .execute(
                "INSERT INTO consensus_membership_terminal_history (transition_id, storage_configuration_epoch, transition_digest, outcome, expected_member_count, transition_start_index, learners_ready_index, joint_membership_index, uniform_membership_index, cutover_index, finalization_index, abort_decision_index, abort_cleanup_membership_index) VALUES (?1, 1, ?2, 1, 3, 1, NULL, NULL, NULL, NULL, NULL, 2, 3)",
                rusqlite::params![[0x41_u8; 16].as_slice(), [0x42_u8; 32].as_slice()],
            )
            .expect("insert retained terminal outcome");

        assert_ne!(
            current_checkpoint_digest(&without_history),
            current_checkpoint_digest(&with_history),
            "recovery quorum voting must distinguish divergent terminal ledgers"
        );
        assert_eq!(
            current_checkpoint_digest(&missing_history),
            current_checkpoint_digest(&without_history),
            "a pre-feature replica must match an explicitly empty terminal ledger"
        );
    }

    #[test]
    fn fenced_transition_activation_state_contributes_to_recovery_digest() {
        let missing_ledger = crate::sqlite::SqliteSessionBackend::canonical_schema_connection()
            .expect("canonical database");
        let prepared_ledger = crate::sqlite::SqliteSessionBackend::canonical_schema_connection()
            .expect("canonical database");
        let activated_empty = crate::sqlite::SqliteSessionBackend::canonical_schema_connection()
            .expect("canonical database");
        let activated_certificate_a =
            crate::sqlite::SqliteSessionBackend::canonical_schema_connection()
                .expect("canonical database");
        let activated_certificate_b =
            crate::sqlite::SqliteSessionBackend::canonical_schema_connection()
                .expect("canonical database");
        let activated_receipt = crate::sqlite::SqliteSessionBackend::canonical_schema_connection()
            .expect("canonical database");
        for conn in [
            &missing_ledger,
            &prepared_ledger,
            &activated_empty,
            &activated_certificate_a,
            &activated_certificate_b,
            &activated_receipt,
        ] {
            consensus::install_recovery_validation_schema_sync(conn, false)
                .expect("install consensus schema");
            conn.execute(
                "INSERT INTO consensus_identity (singleton, schema_version, cluster_id, configuration_id, configuration_epoch) VALUES (1, ?1, ?2, ?3, 1)",
                rusqlite::params![
                    i64::from(SESSION_CONSENSUS_SCHEMA_VERSION),
                    [0x51_u8; 32].as_slice(),
                    [0x52_u8; 32].as_slice(),
                ],
            )
            .expect("insert storage identity");
        }
        missing_ledger
            .execute_batch(
                r#"
                DROP TABLE consensus_fenced_transition_receipts;
                DROP TABLE consensus_fenced_transition_activation;
                ALTER TABLE consensus_identity
                DROP COLUMN fenced_transition_receipt_ledger_activated;
                "#,
            )
            .expect("restore published #684 receipt shape");
        validate_exact_recovery_schema(&missing_ledger, false)
            .expect("exact markerless #684 remains inspection-compatible");
        for conn in [
            &activated_empty,
            &activated_certificate_a,
            &activated_certificate_b,
            &activated_receipt,
        ] {
            conn.execute(
                "UPDATE consensus_identity SET schema_version = ?1, fenced_transition_receipt_ledger_activated = 1 WHERE singleton = 1",
                [i64::from(SESSION_CONSENSUS_SCHEMA_VERSION) + 1],
            )
            .expect("form activated fixture");
        }
        for (conn, digest) in [
            (&activated_certificate_a, [0x56_u8; 32]),
            (&activated_certificate_b, [0x57_u8; 32]),
        ] {
            conn.execute(
                "INSERT INTO consensus_fenced_transition_activation (singleton, storage_configuration_epoch, scope_configuration_id, scope_configuration_epoch, voter_set_digest) VALUES (1, 1, ?1, 1, ?2)",
                rusqlite::params![[0x53_u8; 32].as_slice(), digest.as_slice()],
            )
            .expect("insert activated certificate fixture");
        }
        activated_receipt
            .execute(
                "INSERT INTO consensus_fenced_transition_receipts (request_id, configuration_epoch, payload_digest, retained_until, binding_digest, response_json, response_digest) VALUES (?1, 1, ?2, ?3, ?4, NULL, NULL)",
                rusqlite::params![
                    [0x53_u8; 16].as_slice(),
                    [0x54_u8; 32].as_slice(),
                    "2026-08-17T00:00:00.000000000Z",
                    [0x55_u8; 32].as_slice(),
                ],
            )
            .expect("insert retained request binding");

        assert_eq!(
            current_checkpoint_digest(&missing_ledger),
            current_checkpoint_digest(&prepared_ledger),
            "an empty Prepared layout remains recovery-equivalent to exact #684",
        );
        assert_ne!(
            current_checkpoint_digest(&prepared_ledger),
            current_checkpoint_digest(&activated_empty),
            "the activated schema fence is distinct even without a certificate",
        );
        assert_ne!(
            current_checkpoint_digest(&activated_certificate_a),
            current_checkpoint_digest(&activated_certificate_b),
            "different activated certificates are distinct recovery evidence",
        );
        assert_ne!(
            current_checkpoint_digest(&activated_empty),
            current_checkpoint_digest(&activated_receipt),
            "a durable request binding must contribute to recovery branch evidence",
        );
    }

    #[test]
    fn recovery_rejects_one_over_the_fenced_history_protocol_cap_before_hashing() {
        let conn = crate::sqlite::SqliteSessionBackend::canonical_schema_connection()
            .expect("canonical database");
        consensus::install_recovery_validation_schema_sync(&conn, false)
            .expect("install consensus schema");
        conn.execute(
            "INSERT INTO consensus_identity (singleton, schema_version, cluster_id, configuration_id, configuration_epoch) VALUES (1, ?1, ?2, ?3, 1)",
            rusqlite::params![
                i64::from(SESSION_CONSENSUS_SCHEMA_VERSION),
                [0x57_u8; 32].as_slice(),
                [0x58_u8; 32].as_slice(),
            ],
        )
        .expect("insert storage identity");
        let mut insert = conn
            .prepare(
                "INSERT INTO consensus_fenced_transition_receipts (request_id, configuration_epoch, payload_digest, retained_until, binding_digest, response_json, response_digest) VALUES (?1, 1, ?2, ?3, ?4, NULL, NULL)",
            )
            .expect("prepare receipt fixture");
        for ordinal in 1..=FENCED_TRANSITION_MAX_HISTORY_ENTRIES + 1 {
            let mut request_id = [0x55_u8; 16];
            request_id[8..].copy_from_slice(
                &u64::try_from(ordinal)
                    .expect("fixture ordinal")
                    .to_be_bytes(),
            );
            insert
                .execute(rusqlite::params![
                    request_id.as_slice(),
                    [0x56_u8; 32].as_slice(),
                    "2026-08-17T00:00:00.000000000Z",
                    [0x57_u8; 32].as_slice(),
                ])
                .expect("insert receipt fixture");
        }
        drop(insert);

        assert!(matches!(
            preflight_fenced_transition_receipt_count(&conn),
            Err(RecoveryError::CorruptReplica)
        ));
        let mut budget = InspectionBudget::new(RecoveryLimits::default());
        let mut hasher = Sha256::new();
        assert!(matches!(
            hash_current_checkpoint(
                &conn,
                &mut budget,
                &mut hasher,
                RecoveryDigest::from_bytes([0_u8; 32]),
            ),
            Err(RecoveryError::CorruptReplica)
        ));
    }

    #[test]
    fn recovery_rejects_one_over_the_v2_history_protocol_cap_before_value_scans() {
        let conn = crate::sqlite::SqliteSessionBackend::canonical_schema_connection()
            .expect("canonical database");
        conn.execute_batch(
            "CREATE TABLE consensus_fenced_transition_v2_receipts (request_id BLOB PRIMARY KEY)",
        )
        .expect("receipt fixture schema");
        conn.execute_batch(
            r#"
WITH digits(value) AS (VALUES(0),(1),(2),(3),(4),(5),(6),(7),(8),(9)),
thousands(value) AS (
    SELECT a.value + 10 * b.value + 100 * c.value
    FROM digits AS a CROSS JOIN digits AS b CROSS JOIN digits AS c
),
ordinals(value) AS (
    SELECT low.value + 1000 * high.value
    FROM thousands AS low CROSS JOIN thousands AS high
    UNION ALL
    SELECT 1000000 + low.value + 1000 * high.value
    FROM thousands AS low CROSS JOIN thousands AS high
    WHERE low.value + 1000 * high.value < 48577
)
INSERT INTO consensus_fenced_transition_v2_receipts (request_id)
SELECT CAST(printf('%056d', value) AS BLOB)
FROM ordinals
WHERE value <= 1048576;
"#,
        )
        .expect("one-over V2 receipt fixture");

        assert!(matches!(
            preflight_fenced_transition_v2_receipt_count(&conn),
            Err(RecoveryError::CorruptReplica)
        ));
    }

    #[test]
    fn recovery_rejects_receipt_specific_widths_before_hashing_values() {
        let conn = crate::sqlite::SqliteSessionBackend::canonical_schema_connection()
            .expect("canonical database");
        consensus::install_recovery_validation_schema_sync(&conn, false)
            .expect("install consensus schema");
        conn.execute(
            "INSERT INTO consensus_identity (singleton, schema_version, cluster_id, configuration_id, configuration_epoch) VALUES (1, ?1, ?2, ?3, 1)",
            rusqlite::params![
                i64::from(SESSION_CONSENSUS_SCHEMA_VERSION),
                [0x61_u8; 32].as_slice(),
                [0x62_u8; 32].as_slice(),
            ],
        )
        .expect("insert storage identity");
        conn.execute(
            "INSERT INTO consensus_fenced_transition_receipts (request_id, configuration_epoch, payload_digest, retained_until, binding_digest, response_json, response_digest) VALUES (?1, 1, ?2, ?3, ?4, NULL, NULL)",
            rusqlite::params![
                [0x63_u8; 16].as_slice(),
                [0x64_u8; 32].as_slice(),
                "2026-08-17T00:00:00.000000000Z",
                [0x65_u8; 32].as_slice(),
            ],
        )
        .expect("insert receipt fixture");
        conn.execute_batch("PRAGMA ignore_check_constraints = ON")
            .expect("allow corrupt receipt widths");

        for corruption in ["retention-one-over", "response-one-over"] {
            match corruption {
                "retention-one-over" => conn.execute(
                    "UPDATE consensus_fenced_transition_receipts SET retained_until = ?1",
                    ["0".repeat(
                        consensus::FENCED_TRANSITION_RECEIPT_TIMESTAMP_BYTES + 1,
                    )],
                ),
                "response-one-over" => conn.execute(
                    "UPDATE consensus_fenced_transition_receipts SET response_json = ?1, response_digest = ?2",
                    rusqlite::params![
                        vec![
                            0x66_u8;
                            consensus::FENCED_TRANSITION_RECEIPT_MAX_RESPONSE_BYTES + 1
                        ],
                        [0x67_u8; 32].as_slice(),
                    ],
                ),
                _ => unreachable!("fixed corruption fixture"),
            }
            .expect("inject corrupt receipt width");

            let budget = InspectionBudget::new(RecoveryLimits::default());
            assert!(matches!(
                preflight_current_tables(&conn, &budget),
                Err(RecoveryError::CorruptReplica)
            ));
            let mut budget = InspectionBudget::new(RecoveryLimits::default());
            let mut hasher = Sha256::new();
            assert!(matches!(
                hash_current_checkpoint(
                    &conn,
                    &mut budget,
                    &mut hasher,
                    RecoveryDigest::from_bytes([0_u8; 32]),
                ),
                Err(RecoveryError::CorruptReplica)
            ));

            conn.execute(
                "UPDATE consensus_fenced_transition_receipts SET retained_until = ?1, response_json = NULL, response_digest = NULL",
                ["2026-08-17T00:00:00.000000000Z"],
            )
            .expect("restore canonical receipt widths");
        }
        conn.execute_batch("PRAGMA ignore_check_constraints = OFF")
            .expect("restore receipt constraints");
    }
}

#[cfg(test)]
mod lease_acquired_at_recovery_tests {
    use std::str::FromStr;
    use std::time::Duration;

    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

    use super::*;
    use crate::{OwnerId, SessionKey, SessionKeyType, SqliteSessionBackend};

    fn key() -> SessionKey {
        SessionKey {
            tenant: TenantId::from_static("recovery-acquired-at-test"),
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"recovery-acquired-at")
                .try_into()
                .expect("valid stable ID"),
        }
    }

    fn timestamp(second: u8) -> Timestamp {
        Timestamp::from_str(&format!("2027-01-01T00:00:{second:02}Z"))
            .expect("valid fixture timestamp")
    }

    fn source_with_lease(path: &Path) -> String {
        drop(SqliteSessionBackend::open(path).expect("source backend"));
        let conn = Connection::open(path).expect("source connection");
        let lease = crate::sqlite::lease::acquire_sync(
            &conn,
            &key(),
            OwnerId::new("recovery-acquired-at-owner").expect("owner"),
            Duration::from_secs(60),
            timestamp(1),
        )
        .expect("source lease");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint source");
        crate::sqlite::ops::format_rfc3339_normalized(lease.acquired_at())
    }

    #[test]
    fn exact_recovery_schema_accepts_only_the_complete_pre_acquisition_layout() {
        let conn = SqliteSessionBackend::canonical_schema_connection().expect("schema");
        consensus::install_recovery_validation_schema_sync(&conn, false)
            .expect("consensus recovery schema");
        conn.execute(
            "INSERT INTO consensus_identity (singleton, schema_version, cluster_id, configuration_id, configuration_epoch) VALUES (1, ?1, ?2, ?3, 1)",
            rusqlite::params![
                i64::from(SESSION_CONSENSUS_SCHEMA_VERSION),
                [0x71_u8; 32].as_slice(),
                [0x72_u8; 32].as_slice(),
            ],
        )
        .expect("insert active schema identity");
        conn.execute_batch("ALTER TABLE leases DROP COLUMN acquired_at")
            .expect("form exact pre-acquisition layout");
        validate_exact_recovery_schema(&conn, false)
            .expect("exact pre-acquisition schema is recovery-compatible");

        conn.execute_batch("ALTER TABLE leases ADD COLUMN acquired_at_legacy TEXT")
            .expect("form near-miss layout");
        assert!(matches!(
            validate_exact_recovery_schema(&conn, false),
            Err(RecoveryError::CorruptReplica)
        ));
    }

    #[test]
    fn pre_acquisition_recovery_rejects_noncanonical_guard_expiry() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("source.sqlite");
        let destination = directory.path().join("destination.sqlite");
        source_with_lease(&source);
        let conn = Connection::open(&source).expect("source connection");
        conn.execute_batch("ALTER TABLE leases DROP COLUMN acquired_at")
            .expect("form pre-acquisition source schema");
        let canonical_guard_expiry: String = conn
            .query_row("SELECT guard_expires_at FROM leases", [], |row| row.get(0))
            .expect("read canonical guard expiry");
        let noncanonical_guard_expiry = canonical_guard_expiry
            .strip_suffix(".000000000Z")
            .map(|prefix| format!("{prefix}Z"))
            .expect("fixture uses normalized guard expiry");
        conn.execute(
            "UPDATE leases SET guard_expires_at = ?1",
            [noncanonical_guard_expiry],
        )
        .expect("inject noncanonical guard expiry");
        let mut budget = InspectionBudget::new(RecoveryLimits::default());
        assert!(matches!(
            validate_legacy_lease_state(&conn, &mut budget),
            Err(RecoveryError::CorruptReplica)
        ));
        drop(conn);

        assert!(matches!(
            convert_legacy_checkpoint(&source, &destination, RecoveryLimits::default()),
            Err(RecoveryError::CorruptReplica)
        ));
    }

    #[test]
    fn legacy_checkpoint_conversion_preserves_or_explicitly_marks_acquired_at() {
        for legacy_schema in [false, true] {
            let directory = tempfile::tempdir().expect("temporary directory");
            let source = directory.path().join("source.sqlite");
            let destination = directory.path().join("destination.sqlite");
            let expected = source_with_lease(&source);
            if legacy_schema {
                Connection::open(&source)
                    .expect("open source fixture")
                    .execute_batch("ALTER TABLE leases DROP COLUMN acquired_at; PRAGMA wal_checkpoint(TRUNCATE);")
                    .expect("form pre-acquisition source schema");
            }

            convert_legacy_checkpoint(&source, &destination, RecoveryLimits::default())
                .expect("bounded legacy checkpoint conversion");
            let destination = Connection::open(destination).expect("open converted checkpoint");
            let acquired_at: Option<String> = destination
                .query_row("SELECT acquired_at FROM leases", [], |row| row.get(0))
                .expect("read converted acquisition timestamp");
            assert_eq!(
                acquired_at,
                (!legacy_schema).then_some(expected),
                "legacy_schema={legacy_schema}"
            );
        }
    }
}
