//! Count retained collections before constructing their owned elements.
//!
//! The preflight representation has only inline fields and array counts. It
//! deliberately uses the existing field types and serde struct conventions,
//! including sequence-form structs, omitted Options and ignored extension
//! fields within those types. No serde Value or row-sized SDK copy is needed.
//! This does not bound serde parser scratch or error formatting; it bounds the
//! three owned ledger collections and their fixed-size element/Box shapes.

use std::fmt;
use std::marker::PhantomData;

use serde::de::{DeserializeSeed, Error, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::audit_authority::continuity::chain::{ContinuityState, SignedAuditRow};
use crate::audit_authority::ledger::{
    LedgerEntry, LedgerOperation, LedgerState, MAX_LEDGER_EVENTS, MAX_LEDGER_OPERATIONS,
};
use crate::audit_authority::{AuditLedgerLimits, AuditToken};
use crate::ConfigConsensusIdentity;

use super::{invalid, StoredLedger};
#[cfg(feature = "dangerous-test-hooks")]
use crate::consensus::capacity_observation::{NativePhase, NativePhaseGuard};

struct Count<const MAX: usize>(usize);

impl<'de, const MAX: usize> Deserialize<'de> for Count<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Counter<const MAX: usize>;
        impl<'de, const MAX: usize> Visitor<'de> for Counter<MAX> {
            type Value = Count<MAX>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded retained ledger array")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut count = 0;
                while sequence.next_element::<IgnoredAny>()?.is_some() {
                    if count == MAX {
                        return Err(A::Error::custom("retained ledger array exceeds its limit"));
                    }
                    count += 1;
                }
                Ok(Count(count))
            }
        }
        deserializer.deserialize_seq(Counter::<MAX>)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    identity: ConfigConsensusIdentity,
    ledger: Option<LedgerHeader>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerHeader {
    version: u16,
    identity: ConfigConsensusIdentity,
    projection: AuditToken,
    limits: AuditLedgerLimits,
    sequence: u64,
    terminal: [u8; 32],
    floor: u64,
    predecessor: [u8; 32],
    entries: Count<MAX_LEDGER_EVENTS>,
    operations: Count<MAX_LEDGER_OPERATIONS>,
    continuity: Option<ContinuityHeader>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContinuityHeader {
    version: u16,
    initial_epoch: u64,
    floor_epoch: u64,
    floor_anchor: [u8; 32],
    active_epoch: u64,
    terminal: [u8; 32],
    rows: Count<MAX_LEDGER_EVENTS>,
    checkpoint: Option<crate::audit_authority::continuity::AuditCheckpoint>,
    export_checkpoint: Option<crate::audit_authority::continuity::AuditCheckpoint>,
}

// The header above validates every count and scalar before any retained
// collection is allocated. A second traversal constructs all three collections
// together, rather than restarting at the beginning of the SQL row for each one.
// Header scalars need not be decoded again from the same immutable borrowed row.
#[derive(Clone, Copy)]
struct Field {
    name: &'static str,
    position: usize,
}

const LEDGER: Field = Field {
    name: "ledger",
    position: 1,
};
const ROWS: Field = Field {
    name: "rows",
    position: 6,
};

struct KeyMatches(&'static str);

impl Visitor<'_> for KeyMatches {
    type Value = bool;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a retained ledger field name")
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<bool, E> {
        Ok(value == self.0)
    }
}

impl<'de> DeserializeSeed<'de> for KeyMatches {
    type Value = bool;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<bool, D::Error> {
        deserializer.deserialize_identifier(self)
    }
}

struct Selected<S> {
    path: &'static [Field],
    seed: S,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Selected<S> {
    type Value = S::Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        if self.path.is_empty() {
            self.seed.deserialize(deserializer)
        } else {
            deserializer.deserialize_any(self)
        }
    }
}

impl<'de, S: DeserializeSeed<'de>> Visitor<'de> for Selected<S> {
    type Value = S::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a retained ledger struct")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let Some((field, remainder)) = self.path.split_first() else {
            return Err(A::Error::custom("missing retained array path"));
        };
        let mut seed = Some(self.seed);
        let mut result = None;
        while let Some(matches) = map.next_key_seed(KeyMatches(field.name))? {
            if matches {
                let seed = seed
                    .take()
                    .ok_or_else(|| A::Error::duplicate_field(field.name))?;
                result = Some(map.next_value_seed(Selected {
                    path: remainder,
                    seed,
                })?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        result.ok_or_else(|| A::Error::missing_field(field.name))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let Some((field, remainder)) = self.path.split_first() else {
            return Err(A::Error::custom("missing retained array path"));
        };
        for _ in 0..field.position {
            sequence
                .next_element::<IgnoredAny>()?
                .ok_or_else(|| A::Error::missing_field(field.name))?;
        }
        let result = sequence
            .next_element_seed(Selected {
                path: remainder,
                seed: self.seed,
            })?
            .ok_or_else(|| A::Error::missing_field(field.name))?;
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        Ok(result)
    }
}

struct Elements<T> {
    count: usize,
    element: PhantomData<T>,
}

impl<T> Elements<T> {
    fn new(count: usize) -> Self {
        Self {
            count,
            element: PhantomData,
        }
    }
}

impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for Elements<T> {
    type Value = Vec<T>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Vec<T>, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, T: Deserialize<'de>> Visitor<'de> for Elements<T> {
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a counted retained ledger array")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Vec<T>, A::Error> {
        let mut values = Vec::new();
        let requested = self.count;
        #[cfg(test)]
        let requested = decode_probe::reserve(requested);
        values
            .try_reserve_exact(requested)
            .map_err(|_| A::Error::custom("retained ledger allocation failed"))?;
        for _ in 0..self.count {
            let value = sequence
                .next_element()?
                .ok_or_else(|| A::Error::custom("retained ledger array count changed"))?;
            values.push(value);
            #[cfg(test)]
            decode_probe::constructed();
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("retained ledger array count changed"));
        }
        Ok(values)
    }
}

#[derive(Clone, Copy)]
struct Counts {
    entries: usize,
    operations: usize,
    rows: Option<usize>,
}

struct Collections {
    entries: Vec<LedgerEntry>,
    operations: Vec<LedgerOperation>,
    rows: Option<Vec<SignedAuditRow>>,
}

struct CollectionKey;

impl Visitor<'_> for CollectionKey {
    type Value = usize;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a retained ledger field name")
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<usize, E> {
        Ok(match value {
            "entries" => 0,
            "operations" => 1,
            "continuity" => 2,
            _ => 3,
        })
    }
}

impl<'de> DeserializeSeed<'de> for CollectionKey {
    type Value = usize;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<usize, D::Error> {
        deserializer.deserialize_identifier(self)
    }
}

impl<'de> DeserializeSeed<'de> for Counts {
    type Value = Collections;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Collections, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Counts {
    type Value = Collections;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the counted retained ledger")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Collections, A::Error> {
        let mut entries = None;
        let mut operations = None;
        let mut rows = None;
        let mut continuity_seen = false;
        while let Some(field) = map.next_key_seed(CollectionKey)? {
            match field {
                0 => {
                    if entries.is_some() {
                        return Err(A::Error::duplicate_field("entries"));
                    }
                    entries = Some(map.next_value_seed(Elements::new(self.entries))?);
                }
                1 => {
                    if operations.is_some() {
                        return Err(A::Error::duplicate_field("operations"));
                    }
                    operations = Some(map.next_value_seed(Elements::new(self.operations))?);
                }
                2 => {
                    if continuity_seen {
                        return Err(A::Error::duplicate_field("continuity"));
                    }
                    continuity_seen = true;
                    if let Some(count) = self.rows {
                        rows = Some(map.next_value_seed(Selected {
                            path: &[ROWS],
                            seed: Elements::new(count),
                        })?);
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        if self.rows.is_some() && rows.is_none() {
            return Err(A::Error::missing_field("continuity"));
        }
        Ok(Collections {
            entries: entries.ok_or_else(|| A::Error::missing_field("entries"))?,
            operations: operations.ok_or_else(|| A::Error::missing_field("operations"))?,
            rows,
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Collections, A::Error> {
        for _ in 0..8 {
            sequence
                .next_element::<IgnoredAny>()?
                .ok_or_else(|| A::Error::custom("missing retained ledger scalar"))?;
        }
        let entries = sequence
            .next_element_seed(Elements::new(self.entries))?
            .ok_or_else(|| A::Error::missing_field("entries"))?;
        let operations = sequence
            .next_element_seed(Elements::new(self.operations))?
            .ok_or_else(|| A::Error::missing_field("operations"))?;
        let rows = if let Some(count) = self.rows {
            Some(
                sequence
                    .next_element_seed(Selected {
                        path: &[ROWS],
                        seed: Elements::new(count),
                    })?
                    .ok_or_else(|| A::Error::missing_field("continuity"))?,
            )
        } else {
            sequence.next_element::<IgnoredAny>()?;
            None
        };
        while sequence.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Collections {
            entries,
            operations,
            rows,
        })
    }
}

fn collections(encoded: &[u8], counts: Counts) -> std::io::Result<Collections> {
    #[cfg(feature = "dangerous-test-hooks")]
    let mut phase = NativePhaseGuard::start(NativePhase::DecodeCollections);
    #[cfg(feature = "dangerous-test-hooks")]
    phase.rows(1, encoded.len());
    #[cfg(test)]
    decode_probe::owned_pass(encoded.len());
    let mut deserializer = serde_json::Deserializer::from_slice(encoded);
    let collections = Selected {
        path: &[LEDGER],
        seed: counts,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| invalid())?;
    deserializer.end().map_err(|_| invalid())?;
    #[cfg(feature = "dangerous-test-hooks")]
    phase.finish();
    Ok(collections)
}

pub(super) fn decode(encoded: &[u8]) -> std::io::Result<StoredLedger> {
    #[cfg(feature = "dangerous-test-hooks")]
    let mut phase = NativePhaseGuard::start(NativePhase::DecodePreflight);
    #[cfg(feature = "dangerous-test-hooks")]
    phase.rows(1, encoded.len());
    #[cfg(test)]
    decode_probe::preflight_pass(encoded.len());
    let header: Header = serde_json::from_slice(encoded).map_err(|_| invalid())?;
    #[cfg(feature = "dangerous-test-hooks")]
    phase.finish();
    let ledger = header
        .ledger
        .map(|header| {
            AuditLedgerLimits::new(header.limits.max_events, header.limits.max_operations)
                .map_err(|_| invalid())?;
            if header.entries.0 > header.limits.max_events
                || header.operations.0 > header.limits.max_operations
                || header
                    .continuity
                    .as_ref()
                    .is_some_and(|chain| chain.rows.0 > header.limits.max_events)
            {
                return Err(invalid());
            }
            // Every count is validated before the first vector reserve or
            // EntryPayload Box construction. Decode every owned collection in
            // this one additional traversal of the immutable SQL row.
            let collections = collections(
                encoded,
                Counts {
                    entries: header.entries.0,
                    operations: header.operations.0,
                    rows: header.continuity.as_ref().map(|chain| chain.rows.0),
                },
            )?;
            let continuity = header
                .continuity
                .map(|chain| {
                    Ok::<_, std::io::Error>(ContinuityState {
                        version: chain.version,
                        initial_epoch: chain.initial_epoch,
                        floor_epoch: chain.floor_epoch,
                        floor_anchor: chain.floor_anchor,
                        active_epoch: chain.active_epoch,
                        terminal: chain.terminal,
                        rows: collections.rows.ok_or_else(invalid)?,
                        checkpoint: chain.checkpoint,
                        export_checkpoint: chain.export_checkpoint,
                    })
                })
                .transpose()?;
            Ok(LedgerState {
                version: header.version,
                identity: header.identity,
                projection: header.projection,
                limits: header.limits,
                sequence: header.sequence,
                terminal: header.terminal,
                floor: header.floor,
                predecessor: header.predecessor,
                entries: collections.entries,
                operations: collections.operations,
                continuity,
            })
        })
        .transpose()?;
    Ok(StoredLedger {
        identity: header.identity,
        ledger,
    })
}

#[cfg(test)]
pub(super) mod decode_probe {
    use std::cell::RefCell;

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) struct Snapshot {
        pub(crate) preflight_passes: usize,
        pub(crate) owned_passes: usize,
        pub(crate) traversed_input_bytes: usize,
        pub(crate) reserve_calls: usize,
        pub(crate) requested_elements: usize,
        pub(crate) constructed_elements: usize,
        pub(crate) allocation_fault_injected: bool,
    }

    struct Probe {
        snapshot: Snapshot,
        fail_after: Option<usize>,
    }

    thread_local! { static ACTIVE: RefCell<Option<Probe>> = const { RefCell::new(None) }; }

    pub(crate) struct Guard {
        active: bool,
    }

    impl Guard {
        pub(crate) fn start(fail_after: Option<usize>) -> Self {
            ACTIVE.with(|slot| {
                assert!(slot.borrow().is_none(), "one decoder probe per thread");
                *slot.borrow_mut() = Some(Probe {
                    snapshot: Snapshot::default(),
                    fail_after,
                });
            });
            Self { active: true }
        }

        pub(crate) fn finish(mut self) -> Snapshot {
            self.active = false;
            ACTIVE.with(|slot| {
                slot.borrow_mut()
                    .take()
                    .expect("active decoder probe")
                    .snapshot
            })
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            if self.active {
                ACTIVE.with(|slot| {
                    slot.borrow_mut().take();
                });
            }
        }
    }

    pub(crate) fn preflight_pass(bytes: usize) {
        ACTIVE.with(|slot| {
            if let Some(probe) = slot.borrow_mut().as_mut() {
                probe.snapshot.preflight_passes += 1;
                probe.snapshot.traversed_input_bytes += bytes;
            }
        });
    }

    pub(crate) fn owned_pass(bytes: usize) {
        ACTIVE.with(|slot| {
            if let Some(probe) = slot.borrow_mut().as_mut() {
                probe.snapshot.owned_passes += 1;
                probe.snapshot.traversed_input_bytes += bytes;
            }
        });
    }

    pub(crate) fn reserve(count: usize) -> usize {
        ACTIVE.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(probe) = slot.as_mut() else {
                return count;
            };
            probe.snapshot.reserve_calls += 1;
            probe.snapshot.requested_elements += count;
            match probe.fail_after {
                Some(0) => {
                    probe.fail_after = None;
                    probe.snapshot.allocation_fault_injected = true;
                    usize::MAX
                }
                Some(remaining) => {
                    probe.fail_after = Some(remaining - 1);
                    count
                }
                None => count,
            }
        })
    }

    pub(crate) fn constructed() {
        ACTIVE.with(|slot| {
            if let Some(probe) = slot.borrow_mut().as_mut() {
                probe.snapshot.constructed_elements += 1;
            }
        });
    }
}
