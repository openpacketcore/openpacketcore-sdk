//! Actual native append inputs and checkpoint caller owners, for tests only.
//!
//! Registry keys include the live SQL connection and exact request. Registries
//! retain weak counter state, never the database, command or payload. Owning
//! wrappers move the original ledger/Vec without cloning and publish release
//! only after dropping that value. These observations are not a memory bound.

use std::cell::RefCell;
use std::collections::hash_map::Entry as MapEntry;
use std::collections::HashMap;
use std::mem::size_of;
use std::ops::Deref;
use std::sync::{Arc, LazyLock, Mutex, Weak};

use opc_consensus::engine::{Entry, EntryPayload};
use opc_consensus::ConsensusRequestId;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::audit_authority::ledger::LedgerState;
use crate::backend::SqliteBackend;
use crate::consensus::audit::AuditCommand;
use crate::consensus::audit_mutation::AuditedConfigEffect;
use crate::consensus::config_capacity_simultaneous_working_tests::ledger::ledger_heap;
use crate::consensus::{ConfigMutationIntent, ConfigRaftTypeConfig, PreparedConfigCommit};

const LEDGER: usize = 0;
const ATTEMPT: usize = 1;
type RequestKey = (usize, ConsensusRequestId);

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct OwnerState {
    pub(crate) live: usize,
    pub(crate) created: usize,
    pub(crate) dropped: usize,
    pub(crate) last_capacity: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct EffectSample {
    pub(crate) same_record: bool,
    pub(crate) same_ciphertext: bool,
    pub(crate) same_ciphertext_digest: bool,
    pub(crate) native_commit_bytes: usize,
    pub(crate) consumed_commit_bytes: usize,
    pub(crate) extra_commit_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CheckpointSample {
    pub(crate) sequence: u64,
    pub(crate) at_submit: [OwnerState; 2],
    pub(crate) at_native: [OwnerState; 2],
    pub(crate) page_bytes: usize,
}

#[derive(Debug, Default)]
pub(crate) struct Results {
    pub(crate) effects: Vec<EffectSample>,
    pub(crate) checkpoints: Vec<CheckpointSample>,
}

struct Shared {
    connection: usize,
    owners: Mutex<[OwnerState; 2]>,
    results: Mutex<Results>,
}

struct Submitted {
    shared: Arc<Shared>,
    sequence: u64,
    at_submit: [OwnerState; 2],
}

type Backends = HashMap<usize, Weak<Shared>>;
type Effects = HashMap<RequestKey, Weak<Shared>>;
type Checkpoints = HashMap<RequestKey, Weak<Submitted>>;
static BACKENDS: LazyLock<Mutex<Backends>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static EFFECTS: LazyLock<Mutex<Effects>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static CHECKPOINTS: LazyLock<Mutex<Checkpoints>> = LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Clone, Copy)]
struct CommitIdentity {
    record: usize,
    ciphertext: usize,
    ciphertext_digest: [u8; 32],
    bytes: usize,
}

impl CommitIdentity {
    fn of(commit: &PreparedConfigCommit) -> Self {
        Self {
            record: std::ptr::from_ref(&commit.record) as usize,
            ciphertext: commit.record.encrypted_blob.as_ptr() as usize,
            ciphertext_digest: Sha256::digest(&commit.record.encrypted_blob).into(),
            bytes: size_of::<PreparedConfigCommit>()
                + commit.record.encrypted_blob.capacity()
                + commit.record.principal.capacity()
                + commit.record.plaintext_digest.capacity()
                + commit.audit.capacity() * size_of::<crate::AuditRecord>()
                + commit
                    .audit
                    .iter()
                    .map(|audit| {
                        audit.yang_path.capacity()
                            + audit.previous_value.as_ref().map_or(0, String::capacity)
                            + audit.new_value.as_ref().map_or(0, String::capacity)
                    })
                    .sum::<usize>(),
        }
    }
}

struct ActiveEffect {
    shared: Arc<Shared>,
    original: CommitIdentity,
}

thread_local! {
    static ACTIVE: RefCell<Option<ActiveEffect>> = const { RefCell::new(None) };
}

fn backend_id(backend: &SqliteBackend) -> usize {
    Arc::as_ptr(&backend.conn()) as usize
}

fn find_backend(backend: &SqliteBackend) -> Option<Arc<Shared>> {
    BACKENDS
        .lock()
        .expect("backend registry")
        .get(&backend_id(backend))
        .and_then(Weak::upgrade)
}

fn insert_vacant<K: std::hash::Hash + Eq, T>(
    map: &mut HashMap<K, Weak<T>>,
    key: K,
    value: &Arc<T>,
) {
    match map.entry(key) {
        MapEntry::Vacant(entry) => {
            entry.insert(Arc::downgrade(value));
        }
        MapEntry::Occupied(_) => panic!("duplicate live native owner registration"),
    }
}

fn remove_same<K: std::hash::Hash + Eq, T>(map: &mut HashMap<K, Weak<T>>, key: &K, value: &Arc<T>) {
    if map
        .get(key)
        .and_then(Weak::upgrade)
        .is_some_and(|current| Arc::ptr_eq(&current, value))
    {
        map.remove(key);
    }
}

pub(crate) struct Registration {
    backend: usize,
    request: RequestKey,
    shared: Arc<Shared>,
}

impl Registration {
    pub(crate) async fn new(backend: &SqliteBackend, request: ConsensusRequestId) -> Self {
        let connection = {
            let owner = backend.conn();
            let conn = owner.lock().await;
            let sql: &Connection = &conn;
            std::ptr::from_ref(sql) as usize
        };
        let shared = Arc::new(Shared {
            connection,
            owners: Mutex::new([OwnerState::default(); 2]),
            results: Mutex::new(Results::default()),
        });
        let backend = backend_id(backend);
        let request = (connection, request);
        insert_vacant(
            &mut BACKENDS.lock().expect("backend registry"),
            backend,
            &shared,
        );
        insert_vacant(
            &mut EFFECTS.lock().expect("effect registry"),
            request,
            &shared,
        );
        Self {
            backend,
            request,
            shared,
        }
    }

    // Join native work first and detach before the underlying backend is freed.
    pub(crate) fn detach(&self) {
        remove_same(
            &mut BACKENDS.lock().expect("backend registry"),
            &self.backend,
            &self.shared,
        );
        remove_same(
            &mut EFFECTS.lock().expect("effect registry"),
            &self.request,
            &self.shared,
        );
    }

    pub(crate) fn finish(&self) -> Results {
        let owners = self.shared.owners.lock().expect("actual owner counts");
        for owner in owners.iter() {
            assert_eq!(owner.live, 0, "all measured caller owners released");
            assert!(
                owner.created >= 2,
                "both real mandatory checkpoints observed"
            );
            assert_eq!(owner.created, owner.dropped);
            assert!(owner.last_capacity > 0);
        }
        std::mem::take(&mut *self.shared.results.lock().expect("native results"))
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.detach();
    }
}

// Unlike a counter-only guard, this owns the actual production local. Removing
// a production drop keeps both its real payload and its observation live.
pub(crate) struct Owned<T> {
    value: Option<T>,
    shared: Option<Arc<Shared>>,
    kind: usize,
}

impl<T> Owned<T> {
    fn new(value: T, shared: Option<Arc<Shared>>, kind: usize, bytes: usize) -> Self {
        if let Some(shared) = &shared {
            let mut owners = shared.owners.lock().expect("actual owner counts");
            let owner = &mut owners[kind];
            assert_eq!(owner.live, 0, "one checkpoint caller per measured backend");
            assert!(bytes > 0);
            owner.live = bytes;
            owner.last_capacity = bytes;
            owner.created += 1;
        }
        Self {
            value: Some(value),
            shared,
            kind,
        }
    }
}

impl<T> Deref for Owned<T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.value.as_ref().expect("live original owner")
    }
}

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        drop(self.value.take());
        if let Some(shared) = &self.shared {
            let mut owners = shared.owners.lock().expect("actual owner counts");
            owners[self.kind].live = 0;
            owners[self.kind].dropped += 1;
        }
    }
}

pub(crate) fn caller_ledger(backend: &SqliteBackend, ledger: LedgerState) -> Owned<LedgerState> {
    let shared = find_backend(backend);
    let bytes = shared.as_ref().map_or(0, |_| ledger_heap(&ledger));
    Owned::new(ledger, shared, LEDGER, bytes)
}

pub(crate) fn attempt_encoding(
    backend: &SqliteBackend,
    command: &AuditCommand,
    encoded: Vec<u8>,
) -> Owned<Vec<u8>> {
    let shared = matches!(command, AuditCommand::Checkpoint(_))
        .then(|| find_backend(backend))
        .flatten();
    let bytes = encoded.capacity();
    Owned::new(encoded, shared, ATTEMPT, bytes)
}

pub(crate) struct Submission {
    request: RequestKey,
    submitted: Arc<Submitted>,
}

impl Submission {
    pub(crate) fn start(
        backend: &SqliteBackend,
        request: ConsensusRequestId,
        command: &AuditCommand,
    ) -> Option<Self> {
        let AuditCommand::Checkpoint(checkpoint) = command else {
            return None;
        };
        let shared = find_backend(backend)?;
        let at_submit = *shared.owners.lock().expect("actual submission owners");
        let request = (shared.connection, request);
        let submitted = Arc::new(Submitted {
            shared,
            sequence: checkpoint.sequence(),
            at_submit,
        });
        insert_vacant(
            &mut CHECKPOINTS.lock().expect("checkpoint registry"),
            request,
            &submitted,
        );
        Some(Self { request, submitted })
    }
}

impl Drop for Submission {
    fn drop(&mut self) {
        remove_same(
            &mut CHECKPOINTS.lock().expect("checkpoint registry"),
            &self.request,
            &self.submitted,
        );
    }
}

pub(crate) struct NativeApply {
    shared: Arc<Shared>,
}

impl NativeApply {
    pub(crate) fn start(
        conn: &Connection,
        entries: &Vec<Entry<ConfigRaftTypeConfig>>,
    ) -> Option<Self> {
        let connection = std::ptr::from_ref(conn) as usize;
        for entry in entries {
            let EntryPayload::Normal(command) = &entry.payload else {
                continue;
            };
            let key = (connection, command.request_id);
            let effect = EFFECTS
                .lock()
                .expect("effect registry")
                .get(&key)
                .and_then(Weak::upgrade);
            if let Some(shared) = effect {
                assert_eq!(entries.len(), 1, "exact public effect apply page");
                let ConfigMutationIntent::AuditedMutation(prepared) = &command.intent else {
                    panic!("registered audited effect");
                };
                let AuditedConfigEffect::BoundedAppend { commit, .. } = &prepared.effect else {
                    panic!("registered bounded append");
                };
                assert!(!commit.record.encrypted_blob.is_empty());
                ACTIVE.with(|slot| {
                    let mut active = slot.borrow_mut();
                    assert!(active.is_none(), "non-nested native effect scope");
                    *active = Some(ActiveEffect {
                        shared: Arc::clone(&shared),
                        original: CommitIdentity::of(commit),
                    });
                });
                return Some(Self { shared });
            }
            let submitted = CHECKPOINTS
                .lock()
                .expect("checkpoint registry")
                .get(&key)
                .and_then(Weak::upgrade);
            if let Some(submitted) = submitted {
                assert_eq!(entries.len(), 1, "exact mandatory checkpoint page");
                let ConfigMutationIntent::ManagementAudit(audit) = &command.intent else {
                    panic!("registered checkpoint command");
                };
                let AuditCommand::Checkpoint(checkpoint) = &**audit else {
                    panic!("registered checkpoint payload");
                };
                assert_eq!(checkpoint.sequence(), submitted.sequence);
                let at_native = *submitted
                    .shared
                    .owners
                    .lock()
                    .expect("actual native owners");
                submitted
                    .shared
                    .results
                    .lock()
                    .expect("native results")
                    .checkpoints
                    .push(CheckpointSample {
                        sequence: checkpoint.sequence(),
                        at_submit: submitted.at_submit,
                        at_native,
                        page_bytes: entries.capacity() * size_of::<Entry<ConfigRaftTypeConfig>>()
                            + size_of::<AuditCommand>(),
                    });
            }
        }
        None
    }
}

impl Drop for NativeApply {
    fn drop(&mut self) {
        ACTIVE.with(|slot| {
            let mut active = slot.borrow_mut();
            if active
                .as_ref()
                .is_some_and(|state| Arc::ptr_eq(&state.shared, &self.shared))
            {
                active.take();
            }
        });
    }
}

// Called on the actual argument consumed by append_prepared_commit_sync. The
// original native Box remains live in this same apply call. Pointer equality
// establishes borrowing; the baseline clone is recorded without failing early.
pub(crate) fn consuming_commit(commit: &PreparedConfigCommit) {
    ACTIVE.with(|slot| {
        let active = slot.borrow();
        let Some(active) = active.as_ref() else {
            return;
        };
        let consumed = CommitIdentity::of(commit);
        let original = active.original;
        let same_record = consumed.record == original.record;
        active
            .shared
            .results
            .lock()
            .expect("native results")
            .effects
            .push(EffectSample {
                same_record,
                same_ciphertext: consumed.ciphertext == original.ciphertext,
                same_ciphertext_digest: consumed.ciphertext_digest == original.ciphertext_digest,
                native_commit_bytes: original.bytes,
                consumed_commit_bytes: consumed.bytes,
                extra_commit_bytes: if same_record { 0 } else { consumed.bytes },
            });
    });
}
