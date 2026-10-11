//! Deterministic RFC 022 consumer model, not a quorum implementation.
//!
//! Dispatch, atomic apply and acknowledgement are separate events. Receipts may
//! be pruned, but neither cancellation nor a read cancels a queued command.
//! Rows contain only the existing authenticated envelope; diagnostics omit it.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RowKey(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub birth: u64,
    pub generation: u64,
}

impl Version {
    pub fn next(self) -> Self {
        Self {
            birth: self.birth,
            generation: self.generation.checked_add(1).unwrap(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequestId {
    pub stamp: u64,
    pub sequence: u64,
}

#[derive(Clone)]
pub struct StoredRow {
    pub version: Version,
    pub sealed_stamp: u64,
    pub envelope: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for StoredRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredRow")
            .field("version", &self.version)
            .field("sealed_stamp", &self.sealed_stamp)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct Mutation {
    pub key: RowKey,
    pub expected: Option<Version>,
    pub value: Option<StoredRow>,
}

#[derive(Clone)]
pub struct Command {
    request: RequestId,
    mutations: Vec<Mutation>,
    digest: [u8; 32],
}

impl Command {
    pub fn new(request: RequestId, mutations: Vec<Mutation>) -> Result<Self, Error> {
        let mut keys = BTreeSet::new();
        if mutations.is_empty() || mutations.iter().any(|m| !keys.insert(m.key)) {
            return Err(Error::InvalidCommand);
        }
        let mut hash = Sha256::new();
        hash.update(b"ike-recovery-fixture-child-cas-v1\0");
        hash.update(request.stamp.to_be_bytes());
        hash.update(request.sequence.to_be_bytes());
        hash.update(u64::try_from(mutations.len()).unwrap().to_be_bytes());
        for m in &mutations {
            hash.update(m.key.0.to_be_bytes());
            hash.update([u8::from(m.expected.is_some())]);
            if let Some(expected) = m.expected {
                hash.update(expected.birth.to_be_bytes());
                hash.update(expected.generation.to_be_bytes());
            }
            hash.update([u8::from(m.value.is_some())]);
            if let Some(value) = &m.value {
                if m.expected.is_some_and(|v| value.version != v.next())
                    || (m.expected.is_none() && value.version.generation != 1)
                    || value.sealed_stamp != request.stamp
                    || value.envelope.is_empty()
                {
                    return Err(Error::InvalidCommand);
                }
                hash.update(value.version.birth.to_be_bytes());
                hash.update(value.version.generation.to_be_bytes());
                hash.update(value.sealed_stamp.to_be_bytes());
                hash.update(u64::try_from(value.envelope.len()).unwrap().to_be_bytes());
                hash.update(&*value.envelope);
            } else if m.expected.is_none() {
                return Err(Error::InvalidCommand);
            }
        }
        Ok(Self {
            request,
            mutations,
            digest: hash.finalize().into(),
        })
    }

    pub fn request(&self) -> RequestId {
        self.request
    }

    pub fn mutations(&self) -> &[Mutation] {
        &self.mutations
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    InvalidCommand,
    RequestDigestMismatch,
    StampFenced,
    SequenceNotNext,
    Unknown,
    CasConflict,
    PriorMayStillApply,
    AcknowledgementMismatch,
    InterruptedBeforePublish,
    InvalidSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    request: RequestId,
    digest: [u8; 32],
    versions: BTreeMap<RowKey, Option<Version>>,
}

impl Receipt {
    pub fn acknowledges(&self, command: &Command) -> Result<(), Error> {
        if self.request != command.request || self.digest != command.digest {
            return Err(Error::AcknowledgementMismatch);
        }
        Ok(())
    }

    pub fn version(&self, key: RowKey) -> Option<Version> {
        self.versions.get(&key).copied().flatten()
    }
}

#[derive(Clone)]
struct Outcome {
    digest: [u8; 32],
    result: Result<Receipt, Error>,
}

/// Only this store issues a fenced current cut. Reading it is not a send permit.
pub struct CurrentCut {
    stamp: u64,
    key: RowKey,
    row: Option<StoredRow>,
    _issued: (),
}

impl CurrentCut {
    pub fn stamp(&self) -> u64 {
        self.stamp
    }
    pub fn key(&self) -> RowKey {
        self.key
    }
    pub fn row(&self) -> Option<&StoredRow> {
        self.row.as_ref()
    }
}

pub struct CasStore {
    rows: BTreeMap<RowKey, StoredRow>,
    queued: BTreeMap<RequestId, Command>,
    outcomes: BTreeMap<RequestId, Outcome>,
    stamp: u64,
    applied_sequence: u64,
    unavailable: bool,
    pub dispatches: u64,
    pub publications: u64,
}

impl CasStore {
    pub fn new(stamp: u64) -> Self {
        Self {
            rows: BTreeMap::new(),
            queued: BTreeMap::new(),
            outcomes: BTreeMap::new(),
            stamp,
            applied_sequence: 0,
            unavailable: false,
            dispatches: 0,
            publications: 0,
        }
    }

    pub fn stamp(&self) -> u64 {
        self.stamp
    }

    pub fn next_request(&self) -> RequestId {
        RequestId {
            stamp: self.stamp,
            sequence: self.applied_sequence.checked_add(1).unwrap(),
        }
    }

    pub fn set_unavailable(&mut self, unavailable: bool) {
        self.unavailable = unavailable;
    }

    pub fn dispatch(&mut self, command: Command) -> Result<(), Error> {
        self.dispatches += 1;
        if self.unavailable {
            return Err(Error::Unavailable);
        }
        if self
            .queued
            .get(&command.request)
            .is_some_and(|old| old.digest != command.digest)
            || self
                .outcomes
                .get(&command.request)
                .is_some_and(|old| old.digest != command.digest)
        {
            return Err(Error::RequestDigestMismatch);
        }
        self.queued.entry(command.request).or_insert(command);
        Ok(())
    }

    pub fn apply(&mut self, request: RequestId) -> Result<(), Error> {
        self.apply_with_cut(request, false)
    }

    /// The cut interrupts after validation and before the atomic publication.
    /// It permits the rekey test to observe both old and new rows at that point.
    pub fn apply_with_cut(
        &mut self,
        request: RequestId,
        interrupt_before_publish: bool,
    ) -> Result<(), Error> {
        if self.unavailable {
            return Err(Error::Unavailable);
        }
        if self.outcomes.contains_key(&request) {
            return Ok(());
        }
        let command = self.queued.get(&request).ok_or(Error::Unknown)?.clone();
        if request.stamp != self.stamp {
            return Err(Error::StampFenced);
        }
        if request.sequence <= self.applied_sequence {
            return Err(Error::Unknown);
        }
        if request.sequence != self.applied_sequence + 1 {
            return Err(Error::SequenceNotNext);
        }
        let result = self.apply_child(&command, interrupt_before_publish);
        if result == Err(Error::InterruptedBeforePublish) {
            return Err(Error::InterruptedBeforePublish);
        }
        self.applied_sequence = request.sequence;
        self.outcomes.insert(
            request,
            Outcome {
                digest: command.digest,
                result,
            },
        );
        Ok(())
    }

    /// Independent child-version boundary. Tests call it directly for a late
    /// apply fault so the outer stamp/sequence guard cannot conceal a missing CAS.
    pub fn apply_child(
        &mut self,
        command: &Command,
        interrupt_before_publish: bool,
    ) -> Result<Receipt, Error> {
        for mutation in &command.mutations {
            if self.rows.get(&mutation.key).map(|row| row.version) != mutation.expected {
                return Err(Error::CasConflict);
            }
        }
        // Stage only this batch's changed children. Cloning every unrelated
        // encrypted row makes a matrix of independent epochs quadratic. The
        // exclusive &mut store and absence of a fallible/yielding publication
        // step keep the modeled cut atomic after all comparisons have passed.
        let staged: Vec<_> = command
            .mutations
            .iter()
            .map(|mutation| (mutation.key, mutation.value.clone()))
            .collect();
        let versions = staged
            .iter()
            .map(|(key, value)| (*key, value.as_ref().map(|row| row.version)))
            .collect();
        if interrupt_before_publish {
            return Err(Error::InterruptedBeforePublish);
        }
        for (key, value) in staged {
            match value {
                Some(row) => {
                    self.rows.insert(key, row);
                }
                None => {
                    self.rows.remove(&key);
                }
            }
        }
        self.publications += 1;
        Ok(Receipt {
            request: command.request,
            digest: command.digest,
            versions,
        })
    }

    pub fn acknowledge(&self, command: &Command) -> Result<Receipt, Error> {
        if self.unavailable {
            return Err(Error::Unavailable);
        }
        let outcome = self.outcomes.get(&command.request).ok_or(Error::Unknown)?;
        if outcome.digest != command.digest {
            return Err(Error::RequestDigestMismatch);
        }
        let receipt = outcome.result.clone()?;
        receipt.acknowledges(command)?;
        Ok(receipt)
    }

    pub fn commit(&mut self, command: &Command) -> Result<Receipt, Error> {
        self.dispatch(command.clone())?;
        self.apply(command.request)?;
        self.acknowledge(command)
    }

    pub fn prune(&mut self, request: RequestId) {
        self.outcomes.remove(&request);
    }

    /// Committed succession makes every command bearing the old stamp inapplicable.
    /// No timer decides this transition, and it does not forget queued writes.
    pub fn succeed(&mut self, next_stamp: u64) {
        assert!(next_stamp > self.stamp);
        self.stamp = next_stamp;
        self.applied_sequence = 0;
    }

    pub fn fenced_read(&self, prior: &Command, key: RowKey) -> Result<CurrentCut, Error> {
        if self.unavailable {
            return Err(Error::Unavailable);
        }
        if prior.request.stamp > self.stamp
            || (prior.request.stamp == self.stamp && prior.request.sequence > self.applied_sequence)
        {
            return Err(Error::PriorMayStillApply);
        }
        if let Some(outcome) = self.outcomes.get(&prior.request) {
            if outcome.digest != prior.digest {
                return Err(Error::RequestDigestMismatch);
            }
        }
        Ok(CurrentCut {
            stamp: self.stamp,
            key,
            row: self.rows.get(&key).cloned(),
            _issued: (),
        })
    }

    /// Re-read an issued cut after same-executor progress. The caller must have
    /// joined/fenced its predecessor to obtain that cut. Refuse every queued
    /// command which could still change this row, including a pruned/unknown
    /// receipt, before issuing the latest committed image.
    pub fn refresh_fenced(&self, prior: &CurrentCut) -> Result<CurrentCut, Error> {
        self.current_after_join(prior, prior.key)
    }

    /// A joined execution scope may read another child after all queued writes
    /// to that child are fenced. A raw inspected row never supplies this cut.
    pub fn current_after_join(&self, prior: &CurrentCut, key: RowKey) -> Result<CurrentCut, Error> {
        if self.unavailable {
            return Err(Error::Unavailable);
        }
        if prior.stamp != self.stamp {
            return Err(Error::StampFenced);
        }
        if self.queued.values().any(|command| {
            command.request.stamp >= self.stamp
                && (command.request.stamp > self.stamp
                    || command.request.sequence > self.applied_sequence)
                && command.mutations.iter().any(|m| m.key == key)
        }) {
            return Err(Error::PriorMayStillApply);
        }
        Ok(CurrentCut {
            stamp: self.stamp,
            key,
            row: self.rows.get(&key).cloned(),
            _issued: (),
        })
    }

    /// A crash harness may observe storage, but this accessor grants no runtime
    /// ownership or proof that an outstanding command can no longer apply.
    pub fn inspect(&self, key: RowKey) -> Option<&StoredRow> {
        self.rows.get(&key)
    }

    /// Crash-harness storage contains encrypted rows only. No key/checkpoint
    /// plaintext or private provider handle is exported to the parent process.
    pub fn encrypted_snapshot(&self) -> Vec<u8> {
        let mut bytes = b"IKES\x01".to_vec();
        bytes.extend_from_slice(&self.stamp.to_be_bytes());
        bytes.extend_from_slice(&u32::try_from(self.rows.len()).unwrap().to_be_bytes());
        for (key, row) in &self.rows {
            for value in [
                key.0,
                row.version.birth,
                row.version.generation,
                row.sealed_stamp,
            ] {
                bytes.extend_from_slice(&value.to_be_bytes());
            }
            bytes.extend_from_slice(&u32::try_from(row.envelope.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(&row.envelope);
        }
        bytes
    }

    /// The harness calls this only after joining the old child process and
    /// committing succession. Old queued commands cannot apply under the new
    /// stamp. Receipt/late-command persistence is tested by the separate store
    /// schedules; this snapshot represents the current committed child cut.
    pub fn reopen_after_join(
        bytes: &[u8],
        new_stamp: u64,
    ) -> Result<(Self, Vec<CurrentCut>), Error> {
        struct Reader<'a>(&'a [u8]);
        impl<'a> Reader<'a> {
            fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
                if len > self.0.len() {
                    return Err(Error::InvalidSnapshot);
                }
                let (value, rest) = self.0.split_at(len);
                self.0 = rest;
                Ok(value)
            }
            fn u64(&mut self) -> Result<u64, Error> {
                Ok(u64::from_be_bytes(
                    self.take(8)?
                        .try_into()
                        .map_err(|_| Error::InvalidSnapshot)?,
                ))
            }
            fn count(&mut self) -> Result<usize, Error> {
                usize::try_from(u32::from_be_bytes(
                    self.take(4)?
                        .try_into()
                        .map_err(|_| Error::InvalidSnapshot)?,
                ))
                .map_err(|_| Error::InvalidSnapshot)
            }
        }
        let mut r = Reader(bytes);
        if r.take(5)? != b"IKES\x01" {
            return Err(Error::InvalidSnapshot);
        }
        let old_stamp = r.u64()?;
        if new_stamp <= old_stamp {
            return Err(Error::StampFenced);
        }
        let count = r.count()?;
        if count > bytes.len() / 36 {
            return Err(Error::InvalidSnapshot);
        }
        let mut store = Self::new(new_stamp);
        let mut cuts = Vec::new();
        for _ in 0..count {
            let key = RowKey(r.u64()?);
            let version = Version {
                birth: r.u64()?,
                generation: r.u64()?,
            };
            let sealed_stamp = r.u64()?;
            let len = r.count()?;
            if len > 128 * 1024 || version.generation == 0 || sealed_stamp > old_stamp {
                return Err(Error::InvalidSnapshot);
            }
            let row = StoredRow {
                version,
                sealed_stamp,
                envelope: Zeroizing::new(r.take(len)?.to_vec()),
            };
            if store.rows.insert(key, row.clone()).is_some() {
                return Err(Error::InvalidSnapshot);
            }
            cuts.push(CurrentCut {
                stamp: new_stamp,
                key,
                row: Some(row),
                _issued: (),
            });
        }
        if !r.0.is_empty() {
            return Err(Error::InvalidSnapshot);
        }
        Ok((store, cuts))
    }
}
