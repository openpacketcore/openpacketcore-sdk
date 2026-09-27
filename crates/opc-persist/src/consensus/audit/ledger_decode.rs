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

use serde::de::{
    DeserializeOwned, DeserializeSeed, Error, IgnoredAny, MapAccess, SeqAccess, Visitor,
};
use serde::{Deserialize, Deserializer};

use crate::audit_authority::continuity::chain::{ContinuityState, SignedAuditRow};
use crate::audit_authority::ledger::{
    LedgerEntry, LedgerOperation, LedgerState, MAX_LEDGER_EVENTS, MAX_LEDGER_OPERATIONS,
};
use crate::audit_authority::{AuditLedgerLimits, AuditToken};
use crate::ConfigConsensusIdentity;

use super::{invalid, StoredLedger};

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

// Names and positions are the existing derived-struct representations. Reading
// a selected array a second time avoids storing every element's raw slice (or
// a serde Value) just to learn its count. The SQL bytes remain immutably borrowed.
#[derive(Clone, Copy)]
struct Field {
    name: &'static str,
    position: usize,
}

const LEDGER: Field = Field {
    name: "ledger",
    position: 1,
};
const ENTRIES: Field = Field {
    name: "entries",
    position: 8,
};
const OPERATIONS: Field = Field {
    name: "operations",
    position: 9,
};
const CONTINUITY: Field = Field {
    name: "continuity",
    position: 10,
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

struct Collection<T> {
    path: &'static [Field],
    count: usize,
    element: PhantomData<T>,
}

impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for Collection<T> {
    type Value = Vec<T>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Vec<T>, D::Error> {
        if self.path.is_empty() {
            deserializer.deserialize_seq(Elements::<T> {
                count: self.count,
                element: PhantomData,
            })
        } else {
            deserializer.deserialize_any(self)
        }
    }
}

impl<'de, T: Deserialize<'de>> Visitor<'de> for Collection<T> {
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a retained ledger struct")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Vec<T>, A::Error> {
        let Some((field, remainder)) = self.path.split_first() else {
            return Err(A::Error::custom("missing retained array path"));
        };
        let mut result = None;
        while let Some(matches) = map.next_key_seed(KeyMatches(field.name))? {
            if matches {
                if result.is_some() {
                    return Err(A::Error::duplicate_field(field.name));
                }
                result = Some(map.next_value_seed(Collection::<T> {
                    path: remainder,
                    count: self.count,
                    element: PhantomData,
                })?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        result.ok_or_else(|| A::Error::missing_field(field.name))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Vec<T>, A::Error> {
        let Some((field, remainder)) = self.path.split_first() else {
            return Err(A::Error::custom("missing retained array path"));
        };
        for _ in 0..field.position {
            sequence
                .next_element::<IgnoredAny>()?
                .ok_or_else(|| A::Error::missing_field(field.name))?;
        }
        let result = sequence
            .next_element_seed(Collection::<T> {
                path: remainder,
                count: self.count,
                element: PhantomData,
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

impl<'de, T: Deserialize<'de>> Visitor<'de> for Elements<T> {
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a counted retained ledger array")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Vec<T>, A::Error> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(self.count)
            .map_err(|_| A::Error::custom("retained ledger allocation failed"))?;
        for _ in 0..self.count {
            let value = sequence
                .next_element()?
                .ok_or_else(|| A::Error::custom("retained ledger array count changed"))?;
            values.push(value);
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(A::Error::custom("retained ledger array count changed"));
        }
        Ok(values)
    }
}

fn collection<T: DeserializeOwned>(
    encoded: &[u8],
    path: &'static [Field],
    count: usize,
) -> std::io::Result<Vec<T>> {
    let mut deserializer = serde_json::Deserializer::from_slice(encoded);
    let values = Collection::<T> {
        path,
        count,
        element: PhantomData,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| invalid())?;
    deserializer.end().map_err(|_| invalid())?;
    Ok(values)
}

pub(super) fn decode(encoded: &[u8]) -> std::io::Result<StoredLedger> {
    let header: Header = serde_json::from_slice(encoded).map_err(|_| invalid())?;
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
            // EntryPayload Box construction. Elements have only fixed-size
            // fields, except for the three closed, fixed-size payload Boxes.
            let entries = collection::<LedgerEntry>(encoded, &[LEDGER, ENTRIES], header.entries.0)?;
            let operations =
                collection::<LedgerOperation>(encoded, &[LEDGER, OPERATIONS], header.operations.0)?;
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
                        rows: collection::<SignedAuditRow>(
                            encoded,
                            &[LEDGER, CONTINUITY, ROWS],
                            chain.rows.0,
                        )?,
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
                entries,
                operations,
                continuity,
            })
        })
        .transpose()?;
    Ok(StoredLedger {
        identity: header.identity,
        ledger,
    })
}
