//! Counters at the consumed reserved preparation boundary. No payload or
//! reservation is retained; finalized nested owners are counted exactly once.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, Weak};

use opc_types::TxId;
use sha2::{Digest, Sha256};

use crate::consensus::PreparedConfigCommit;
use crate::{AuditRecord, CommitRecord};

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Sample {
    pub(crate) old_capacities: [usize; 3],
    pub(crate) new_capacities: [usize; 3],
    pub(crate) post_capacities: [usize; 3],
    pub(crate) ciphertext_bytes: usize,
    pub(crate) alias_bytes: usize,
    pub(crate) nested_bytes: usize,
    pub(crate) total: usize,
    pub(crate) has_reservation: bool,
    pub(crate) copy_observed: bool,
    pub(crate) released: [bool; 3],
}

struct State {
    input_pointers: [usize; 3],
    input_capacities: [usize; 3],
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

fn pointers(record: &CommitRecord, audit: &[AuditRecord]) -> [usize; 3] {
    [
        record.principal.as_ptr() as usize,
        record.plaintext_digest.as_ptr() as usize,
        audit.as_ptr() as usize,
    ]
}

fn capacities(record: &CommitRecord, audit: &Vec<AuditRecord>) -> [usize; 3] {
    [
        record.principal.capacity(),
        record.plaintext_digest.capacity(),
        audit.capacity() * std::mem::size_of::<AuditRecord>(),
    ]
}

// Hash the authenticated finalized fields and each nested owner address/extent
// without allocating serialization buffers or retaining references. Moving the
// outer Vec must preserve those exact already-finalized nested allocations.
fn audit_witness(audit: &[AuditRecord]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(audit.len().to_le_bytes());
    for entry in audit {
        digest.update(entry.sequence.to_le_bytes());
        digest.update(entry.previous_hash);
        digest.update(entry.entry_hmac);
        for value in [
            Some(&entry.yang_path),
            entry.previous_value.as_ref(),
            entry.new_value.as_ref(),
        ] {
            digest.update([u8::from(value.is_some())]);
            if let Some(value) = value {
                digest.update((value.as_ptr() as usize).to_le_bytes());
                digest.update(value.capacity().to_le_bytes());
                digest.update(value.len().to_le_bytes());
                digest.update(value.as_bytes());
            }
        }
    }
    digest.finalize().into()
}

impl Registration {
    pub(crate) fn new(record: &CommitRecord, audit: &Vec<AuditRecord>, alias: &[u8]) -> Self {
        assert_eq!(record.encrypted_blob, alias);
        assert_ne!(record.encrypted_blob.as_ptr(), alias.as_ptr());
        let key = (record.tx_id, record.principal.as_ptr() as usize);
        let state = Arc::new(Mutex::new(State {
            input_pointers: pointers(record, audit),
            input_capacities: capacities(record, audit),
            alias_bytes: alias.len(),
            calls: 0,
            sample: None,
        }));
        assert!(
            REGISTRY
                .lock()
                .expect("transferred owner registry")
                .insert(key, Arc::downgrade(&state))
                .is_none(),
            "one observation per live input allocation"
        );
        Self { key, state }
    }

    pub(crate) fn finish(&self) -> Sample {
        let state = self.state.lock().expect("transferred owner result");
        assert_eq!(state.calls, 1, "exact consumed preparation observed once");
        state.sample.expect("actual reserved preparation observed")
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut registry = REGISTRY.lock().expect("transferred owner registry");
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
    audit_witness: [u8; 32],
    replacement_pointers: Mutex<[Option<usize>; 3]>,
}

pub(crate) fn begin(commit: &PreparedConfigCommit, has_reservation: bool) -> Option<Handoff> {
    // Remove before releasing any input, so address reuse cannot find this observation.
    let key = (
        commit.record.tx_id,
        commit.record.principal.as_ptr() as usize,
    );
    let state = REGISTRY
        .lock()
        .expect("transferred owner registry")
        .remove(&key)
        .and_then(|state| state.upgrade())?;
    {
        let mut observed = state.lock().expect("transferred owner inventory");
        observed.calls += 1;
        assert_eq!(observed.calls, 1);
        assert_eq!(
            pointers(&commit.record, &commit.audit),
            observed.input_pointers
        );
        assert_eq!(
            capacities(&commit.record, &commit.audit),
            observed.input_capacities
        );
        let nested_bytes = commit
            .audit
            .iter()
            .map(|entry| {
                entry.yang_path.capacity()
                    + entry.previous_value.as_ref().map_or(0, String::capacity)
                    + entry.new_value.as_ref().map_or(0, String::capacity)
            })
            .sum();
        let mut sample = Sample {
            old_capacities: observed.input_capacities,
            ciphertext_bytes: commit.record.encrypted_blob.capacity(),
            alias_bytes: observed.alias_bytes,
            nested_bytes,
            has_reservation,
            ..Sample::default()
        };
        sample.total = sample
            .old_capacities
            .into_iter()
            .chain([
                sample.ciphertext_bytes,
                sample.alias_bytes,
                sample.nested_bytes,
            ])
            .try_fold(0_usize, usize::checked_add)
            .expect("finite actual owners");
        observed.sample = Some(sample);
    }
    Some(Handoff {
        state,
        audit_witness: audit_witness(&commit.audit),
        replacement_pointers: Mutex::new([None; 3]),
    })
}

impl Handoff {
    // The production-removal baseline intentionally has no replacement call.
    #[allow(dead_code)]
    pub(crate) fn before_handoff(
        &self,
        commit: &PreparedConfigCommit,
        principal: Option<&String>,
        digest: Option<&Vec<u8>>,
        audit: Option<&Vec<AuditRecord>>,
    ) {
        if let Some(value) = principal {
            assert_eq!(value, &commit.record.principal);
        }
        if let Some(value) = digest {
            assert_eq!(value, &commit.record.plaintext_digest);
        }
        if let Some(value) = audit {
            assert!(value.is_empty());
        }
        let replacements = [
            principal.map(|value| value.as_ptr() as usize),
            digest.map(|value| value.as_ptr() as usize),
            audit.map(|value| value.as_ptr() as usize),
        ];
        let mut observed = self.state.lock().expect("transferred copy inventory");
        for (old, new) in observed.input_pointers.into_iter().zip(replacements) {
            if let Some(new) = new {
                assert_ne!(old, new);
            }
        }
        let sample = observed.sample.as_mut().expect("original inventory");
        assert!(!sample.copy_observed);
        sample.new_capacities = [
            principal.map_or(0, String::capacity),
            digest.map_or(0, Vec::capacity),
            audit.map_or(0, Vec::capacity) * std::mem::size_of::<AuditRecord>(),
        ];
        sample.total = sample
            .new_capacities
            .into_iter()
            .try_fold(sample.total, usize::checked_add)
            .expect("actual simultaneous old/new owners");
        sample.copy_observed = replacements.iter().any(Option::is_some);
        *self
            .replacement_pointers
            .lock()
            .expect("replacement addresses") = replacements;
    }

    pub(crate) fn after_handoff(self, commit: &PreparedConfigCommit) {
        assert_eq!(
            audit_witness(&commit.audit),
            self.audit_witness,
            "exact finalized audit fields and nested allocations moved once"
        );
        let mut observed = self.state.lock().expect("transferred release inventory");
        let replacements = *self
            .replacement_pointers
            .lock()
            .expect("replacement addresses");
        let expected: [usize; 3] = std::array::from_fn(|index| {
            replacements[index].unwrap_or(observed.input_pointers[index])
        });
        assert_eq!(pointers(&commit.record, &commit.audit), expected);
        let sample = observed.sample.as_mut().expect("original inventory");
        sample.post_capacities = capacities(&commit.record, &commit.audit);
        sample.released = replacements.map(|pointer| pointer.is_some());
        for index in 0..3 {
            assert_eq!(
                sample.post_capacities[index],
                if sample.released[index] {
                    sample.new_capacities[index]
                } else {
                    sample.old_capacities[index]
                }
            );
        }
    }
}
