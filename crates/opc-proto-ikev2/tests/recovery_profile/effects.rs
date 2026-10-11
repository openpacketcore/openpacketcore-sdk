//! Consumer effect fence. Recovery reads opaque committed outcomes without
//! recreating an SDK completion token. The sink keeps an operation identity
//! across process/owner changes so applying the same result is idempotent.

use super::{
    codec::ProfileCodec,
    driver::{self, Runtime},
    envelope::{self, Provider},
    ke,
    store::{CasStore, Command, CurrentCut, RowKey},
    wire::Wire,
};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Direction {
    Local,
    Peer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Driver(driver::Error),
    NotCommitted,
    ConflictingOutcome,
}

impl From<driver::Error> for Error {
    fn from(error: driver::Error) -> Self {
        Self::Driver(error)
    }
}

#[derive(Default)]
pub struct Effects {
    applied: BTreeMap<(RowKey, u64, Direction, u32), [u8; 32]>,
    pub outcomes: Vec<Bytes>,
}

impl Effects {
    /// The independent sink survives loss of the IKE executor. This image has
    /// only idempotency identities and digests, never keys or outcome plaintext.
    pub fn snapshot(&self) -> Vec<u8> {
        let mut bytes = b"IKEE\x01".to_vec();
        bytes.extend_from_slice(&u32::try_from(self.applied.len()).unwrap().to_be_bytes());
        for ((key, birth, direction, id), digest) in &self.applied {
            bytes.extend_from_slice(&key.0.to_be_bytes());
            bytes.extend_from_slice(&birth.to_be_bytes());
            bytes.push(u8::from(*direction == Direction::Peer));
            bytes.extend_from_slice(&id.to_be_bytes());
            bytes.extend_from_slice(digest);
        }
        bytes
    }

    pub fn reopen(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 9 || &bytes[..5] != b"IKEE\x01" {
            return Err(Error::NotCommitted);
        }
        let count = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
        if count.checked_mul(53).and_then(|len| len.checked_add(9)) != Some(bytes.len()) {
            return Err(Error::NotCommitted);
        }
        let mut sink = Self::default();
        for entry in bytes[9..].as_chunks::<53>().0 {
            let key = RowKey(u64::from_be_bytes(entry[..8].try_into().unwrap()));
            let birth = u64::from_be_bytes(entry[8..16].try_into().unwrap());
            let direction = match entry[16] {
                0 => Direction::Local,
                1 => Direction::Peer,
                _ => return Err(Error::NotCommitted),
            };
            let id = u32::from_be_bytes(entry[17..21].try_into().unwrap());
            let digest = entry[21..].try_into().unwrap();
            if sink
                .applied
                .insert((key, birth, direction, id), digest)
                .is_some()
            {
                return Err(Error::ConflictingOutcome);
            }
        }
        Ok(sink)
    }

    pub fn len(&self) -> usize {
        self.applied.len()
    }

    /// No caller-supplied candidate or outcome is accepted. Re-read the exact
    /// current row after fencing all possible late applies, check the runtime
    /// reconciled it, then hold current owner authority through the effect.
    pub fn apply(
        &mut self,
        provider: &Provider,
        store: &CasStore,
        prior: &Command,
        runtime: &Runtime,
        direction: Direction,
    ) -> Result<bool, Error> {
        if runtime.pending.is_some() {
            return Err(Error::NotCommitted);
        }
        let cut = store
            .fenced_read(prior, runtime.row.key)
            .map_err(driver::Error::from)?;
        self.apply_fenced(provider, &cut, runtime, direction)
    }

    pub fn recover(
        &mut self,
        provider: &Provider,
        store: &CasStore,
        joined: &CurrentCut,
        runtime: &Runtime,
        direction: Direction,
    ) -> Result<bool, Error> {
        if runtime.pending.is_some() {
            return Err(Error::NotCommitted);
        }
        let cut = store.refresh_fenced(joined).map_err(driver::Error::from)?;
        self.apply_fenced(provider, &cut, runtime, direction)
    }

    fn apply_fenced(
        &mut self,
        provider: &Provider,
        cut: &CurrentCut,
        runtime: &Runtime,
        direction: Direction,
    ) -> Result<bool, Error> {
        let permit = runtime.permit();
        permit.check().map_err(driver::Error::from)?;
        if runtime.pending.is_some() || runtime.row.closed {
            return Err(Error::NotCommitted);
        }
        let stored = cut.row().ok_or(Error::NotCommitted)?;
        let plain = envelope::unseal(provider, cut.key(), stored).map_err(driver::Error::from)?;
        let row = ProfileCodec::decode(&plain, cut.key(), stored.version, stored.sealed_stamp)
            .map_err(driver::Error::from)?;
        ke::validate_row(&row).map_err(driver::Error::from)?;
        if row.closed
            || row.version != runtime.row.version
            || permit.binding() != (row.key, row.version.birth, cut.stamp())
        {
            return Err(Error::NotCommitted);
        }
        let entry = match direction {
            Direction::Local => row.window.outbound.as_ref(),
            Direction::Peer => row.window.inbound.as_ref(),
        }
        .ok_or(Error::NotCommitted)?;
        let response = entry.response().ok_or(Error::NotCommitted)?;
        let outcome = entry.outcome().ok_or(Error::NotCommitted)?;
        let receiving = match direction {
            Direction::Local => crate::canonical_fixtures::opposite(row.direction),
            Direction::Peer => row.direction,
        };
        let request = Wire::new(row.profile, &row.keys, row.spis, receiving)
            .open(entry.request())
            .map_err(|_| Error::NotCommitted)?;
        let key = (
            row.key,
            row.version.birth,
            direction,
            request.header.message_id,
        );
        let mut hash = Sha256::new();
        hash.update(b"ike-fixture-committed-effect-v1\0");
        for field in [entry.request(), response, outcome] {
            hash.update(u64::try_from(field.len()).unwrap().to_be_bytes());
            hash.update(field);
        }
        let digest = hash.finalize().into();
        permit
            .while_current(|| {
                if let Some(old) = self.applied.get(&key) {
                    return if *old == digest {
                        Ok(false)
                    } else {
                        Err(Error::ConflictingOutcome)
                    };
                }
                self.applied.insert(key, digest);
                self.outcomes.push(Bytes::copy_from_slice(outcome));
                Ok(true)
            })
            .map_err(driver::Error::from)?
    }
}
