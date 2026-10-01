//! Actual old/new/alias overlap at the consumed reserved preparation boundary.
//! The registry retains counters and addresses, never a payload or reservation.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, Weak};

use crate::consensus::PreparedConfigCommit;
use crate::CommitRecord;
use opc_types::TxId;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Sample {
    pub(crate) old_capacity: usize,
    pub(crate) new_capacity: usize,
    pub(crate) alias_bytes: usize,
    pub(crate) other_owned: usize,
    pub(crate) total: usize,
    pub(crate) post_capacity: usize,
    pub(crate) has_reservation: bool,
    pub(crate) same_bytes: bool,
    pub(crate) old_owner_released: bool,
}

struct State {
    input_pointer: usize,
    input_capacity: usize,
    alias_pointer: usize,
    alias_bytes: usize,
    calls: usize,
    sample: Option<Sample>,
}

type ObservationKey = (TxId, usize);
type Registry = HashMap<ObservationKey, Weak<Mutex<State>>>;
static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| Mutex::new(HashMap::new()));

pub(crate) struct Registration {
    key: ObservationKey,
    state: Arc<Mutex<State>>,
}

impl Registration {
    pub(crate) fn new(record: &CommitRecord, encryption_alias: &[u8]) -> Self {
        assert_eq!(
            record.encrypted_blob, encryption_alias,
            "exact real encryption owner"
        );
        assert_ne!(record.encrypted_blob.as_ptr(), encryption_alias.as_ptr());
        let state = Arc::new(Mutex::new(State {
            input_pointer: record.encrypted_blob.as_ptr() as usize,
            input_capacity: record.encrypted_blob.capacity(),
            alias_pointer: encryption_alias.as_ptr() as usize,
            alias_bytes: encryption_alias.len(),
            calls: 0,
            sample: None,
        }));
        let key = (record.tx_id, record.encrypted_blob.as_ptr() as usize);
        let inserted = {
            let mut registry = REGISTRY.lock().expect("normalization registry");
            match registry.entry(key) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(Arc::downgrade(&state));
                    true
                }
                std::collections::hash_map::Entry::Occupied(_) => false,
            }
        };
        assert!(inserted, "one observer per live input allocation");
        Self { key, state }
    }

    pub(crate) fn finish(&self) -> Option<Sample> {
        let state = self.state.lock().expect("normalization result");
        assert!(
            state.calls <= 1,
            "the exact preparation normalizes at most once"
        );
        state.sample
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut registry = REGISTRY.lock().expect("normalization registry");
        if registry
            .get(&self.key)
            .is_some_and(|current| Weak::ptr_eq(current, &Arc::downgrade(&self.state)))
        {
            registry.remove(&self.key);
        }
    }
}

pub(crate) struct Handoff {
    state: Arc<Mutex<State>>,
    replacement_pointer: Option<usize>,
}

pub(crate) fn before_handoff(
    commit: &PreparedConfigCommit,
    replacement: Option<&Vec<u8>>,
    has_reservation: bool,
) -> Option<Handoff> {
    // Consume the registration before the original allocation is released.
    // A later allocation may reuse its address without inheriting this observer.
    let key = (
        commit.record.tx_id,
        commit.record.encrypted_blob.as_ptr() as usize,
    );
    let state = REGISTRY
        .lock()
        .expect("normalization registry")
        .remove(&key)
        .and_then(|state| state.upgrade())?;
    let replacement_pointer = replacement.map(|encoded| encoded.as_ptr() as usize);
    {
        let mut observed = state.lock().expect("normalization inventory");
        observed.calls += 1;
        assert_eq!(observed.calls, 1);
        assert_eq!(
            commit.record.encrypted_blob.as_ptr() as usize,
            observed.input_pointer
        );
        assert_eq!(
            commit.record.encrypted_blob.capacity(),
            observed.input_capacity
        );
        if let Some(encoded) = replacement {
            assert_eq!(
                encoded, &commit.record.encrypted_blob,
                "exact bytes coexist before release"
            );
            assert_ne!(encoded.as_ptr() as usize, observed.input_pointer);
            assert_ne!(encoded.as_ptr() as usize, observed.alias_pointer);
        }
        let other_owned = commit.record.plaintext_digest.capacity()
            + commit.record.principal.capacity()
            + commit.audit.capacity() * std::mem::size_of::<crate::AuditRecord>()
            + commit
                .audit
                .iter()
                .map(|record| {
                    record.yang_path.capacity()
                        + record.previous_value.as_ref().map_or(0, String::capacity)
                        + record.new_value.as_ref().map_or(0, String::capacity)
                })
                .sum::<usize>();
        let new_capacity = replacement.map_or(0, Vec::capacity);
        let total = [
            observed.input_capacity,
            new_capacity,
            observed.alias_bytes,
            other_owned,
        ]
        .into_iter()
        .try_fold(0_usize, usize::checked_add)
        .expect("finite actual owners");
        observed.sample = Some(Sample {
            old_capacity: observed.input_capacity,
            new_capacity,
            alias_bytes: observed.alias_bytes,
            other_owned,
            total,
            has_reservation,
            same_bytes: replacement.is_some(),
            ..Sample::default()
        });
    }
    Some(Handoff {
        state,
        replacement_pointer,
    })
}

impl Handoff {
    pub(crate) fn after_handoff(self, commit: &PreparedConfigCommit) {
        let mut observed = self.state.lock().expect("normalization release");
        let pointer = commit.record.encrypted_blob.as_ptr() as usize;
        assert_eq!(
            pointer,
            self.replacement_pointer.unwrap_or(observed.input_pointer)
        );
        let sample = observed
            .sample
            .as_mut()
            .expect("observed old and new owners");
        sample.post_capacity = commit.record.encrypted_blob.capacity();
        sample.old_owner_released = self.replacement_pointer.is_some();
        if self.replacement_pointer.is_some() {
            assert_eq!(sample.post_capacity, sample.new_capacity);
        } else {
            assert_eq!(sample.post_capacity, sample.old_capacity);
        }
    }
}

#[test]
fn normalization_observers_accept_equal_transaction_ids_on_distinct_allocations() {
    let alias = vec![0xAB; 32];
    let first = CommitRecord {
        tx_id: TxId::from_uuid(uuid::Uuid::from_u128(0x9802)),
        parent_tx_id: None,
        version: opc_types::ConfigVersion::new(1),
        committed_at: "1970-01-01T00:01:40Z".parse().expect("synthetic time"),
        principal: "synthetic-observer".to_string(),
        source: crate::CommitSource::Gnmi,
        schema_digest: opc_types::SchemaDigest::from_bytes([0xAA; 32]),
        plaintext_digest: vec![0xAC; 32],
        encrypted_blob: alias.clone(),
        rollback_point: false,
        confirmed_deadline: None,
    };
    let second = first.clone();
    assert_ne!(
        first.encrypted_blob.as_ptr(),
        second.encrypted_blob.as_ptr()
    );
    let first_observer = Registration::new(&first, &alias);
    let second_observer = Registration::new(&second, &alias);
    assert!(first_observer.finish().is_none());
    drop(first_observer);
    assert!(second_observer.finish().is_none());
    assert!(
        REGISTRY
            .lock()
            .expect("normalization registry")
            .values()
            .any(|current| Weak::ptr_eq(current, &Arc::downgrade(&second_observer.state))),
        "dropping one original must preserve the other observer"
    );
}
