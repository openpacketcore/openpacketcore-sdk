//! Small comparison metadata from a fully authenticated carrier. No decoded
//! canonical body, borrowed key or serialized admission certificate survives.
//! The catalog owns this prospective resident index under whole-process RSS;
//! final row construction still reopens and authenticates the selected range.

use super::super::generation::facts::{Business, Key, KeyId};
use super::*;

struct Reservation {
    key: KeyId,
    expected: Business,
}

pub(in crate::consensus::native) struct Metadata {
    pub(in crate::consensus::native) content: [u8; 32],
    pub(in crate::consensus::native) facts: Facts,
    pub(in crate::consensus::native) charge: ProductionSnapshotAccounting,
    pub(in crate::consensus::native) index: super::index::CatalogEntry,
    projection: [u8; 32],
    admission: [u8; 32],
    terminal: Option<[u8; 32]>,
    reservation: Option<Box<Reservation>>,
}

impl Metadata {
    pub(in crate::consensus::native) fn of(
        hydrated: &carrier::Hydration,
        sequence: u64,
        applied: Option<u64>,
        witness: Option<GlobalChargeWitness>,
    ) -> io::Result<Self> {
        // Covers the sole optional independent key and comparison metadata
        // until it transfers into the prospective resident catalog. Original
        // provenance/business serialization runs under the hydration guard.
        let _memory = VerificationMemory::reserve(4096)?;
        let expected = match hydrated.body() {
            carrier::Body::V1(row) => row
                .record()
                .business_reservation()
                .map(|reservation| Business::of(reservation.expected()))
                .transpose()?,
            carrier::Body::V2(row) => row.record().absence_reservation().map(|_| Business::Absent),
        };
        let reservation = match (hydrated.reserved_key(), expected) {
            (None, None) => None,
            (Some(key), Some(expected)) => Some(Box::new(Reservation {
                key: KeyId::of(key)?,
                expected,
            })),
            _ => {
                return Err(invalid(
                    "native catalog roster business predicate is incomplete",
                ))
            }
        };
        let (admission, terminal) = hydrated
            .history_commitments()
            .map_err(|_| invalid("native catalog signed history comparison failed"))?;
        Ok(Self {
            content: Row::hydration_fingerprint(hydrated)?,
            facts: hydrated.facts,
            charge: accounting(hydrated, sequence, applied, witness)?,
            index: super::index::CatalogEntry::of(hydrated)?,
            projection: super::super::changes::fingerprint(
                4,
                &hydrated.binding(),
                &hydrated.projection,
            )?,
            admission,
            terminal,
            reservation,
        })
    }

    pub(in crate::consensus::native) fn key(&self) -> Option<KeyId> {
        self.reservation.as_ref().map(|reservation| reservation.key)
    }

    pub(in crate::consensus::native) fn matches_business(&self, key: Option<&Key>) -> bool {
        match (&self.reservation, key) {
            (None, _) => true,
            (Some(reservation), Some(key)) => key.reserved && key.business == reservation.expected,
            (Some(_), None) => false,
        }
    }

    pub(in crate::consensus::native) fn validate_replacement(
        &self,
        before: &Self,
    ) -> io::Result<()> {
        if self.projection != before.projection || self.admission != before.admission {
            return Err(invalid("native catalog roster admission binding changed"));
        }
        match (before.facts.state, self.facts.state) {
            (State::Live, State::Retained | State::Tombstone) => {}
            (State::Retained, State::Tombstone)
                if self.facts.terminalized_at == before.facts.terminalized_at
                    && self.facts.terminal_sequence == before.facts.terminal_sequence
                    && self.facts.terminal_raft_log_index
                        == before.facts.terminal_raft_log_index
                    && self.terminal == before.terminal => {}
            (left, right) if left == right && self.content == before.content => {}
            _ => {
                return Err(invalid(
                    "native catalog roster terminal history changed or regressed",
                ))
            }
        }
        Ok(())
    }
}
