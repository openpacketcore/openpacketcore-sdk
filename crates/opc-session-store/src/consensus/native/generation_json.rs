//! Allocation-only preflight for the current native raw-log vocabulary.
//! Unknown legacy outer/membership fields retain the complete SQL decoder's
//! compatibility rules. Command body trees are counted without allocating a model;
//! byte arrays are streamed, never collected. Full decoding remains mandatory.

use super::*;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use std::fmt;

const REQUEST_FIELDS: usize = 128;

#[derive(Default, Clone, Copy)]
struct Shape {
    requests: usize,
    payload: usize,
}

#[derive(Default)]
struct Body {
    fields: usize,
    containers: usize,
    payload: usize,
}

impl Body {
    fn field<E: de::Error>(&mut self) -> Result<(), E> {
        self.fields += 1;
        if self.fields > REQUEST_FIELDS {
            return Err(E::custom("native V2 body metadata exceeds closed shape"));
        }
        Ok(())
    }
    fn container<E: de::Error>(&mut self) -> Result<(), E> {
        self.containers += 1;
        if self.containers > REQUEST_FIELDS {
            return Err(E::custom("native V2 body containers exceed closed shape"));
        }
        Ok(())
    }
}

struct Field;
impl<'de> Deserialize<'de> for Field {
    fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Name;
        impl Visitor<'_> for Name {
            type Value = Field;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded native V2 field name")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Field, E> {
                if value.len() > 128 {
                    return Err(E::custom("native V2 field name exceeds closed shape"));
                }
                Ok(Field)
            }
        }
        decoder.deserialize_identifier(Name)
    }
}

#[derive(Clone, Copy)]
enum Atom {
    Byte,
    Other,
}

struct Scan<'a>(&'a mut Body);
impl<'de> DeserializeSeed<'de> for Scan<'_> {
    type Value = Atom;
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Atom, D::Error> {
        decoder.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Scan<'_> {
    type Value = Atom;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded native V2 request shape")
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Atom, E> {
        Ok(if value <= u8::MAX as u64 {
            Atom::Byte
        } else {
            Atom::Other
        })
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Atom, E> {
        Ok(if (0..=255).contains(&value) {
            Atom::Byte
        } else {
            Atom::Other
        })
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Atom, E> {
        Ok(Atom::Other)
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Atom, E> {
        Ok(Atom::Other)
    }
    fn visit_unit<E: de::Error>(self) -> Result<Atom, E> {
        Ok(Atom::Other)
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Atom, E> {
        if value.len() > 128 {
            return Err(E::custom("native V2 string exceeds closed model shape"));
        }
        Ok(Atom::Other)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Atom, A::Error> {
        self.0.container()?;
        let mut count = 0usize;
        let mut all_bytes = true;
        let mut other = 0usize;
        while let Some(value) = sequence.next_element_seed(Scan(self.0))? {
            count = count
                .checked_add(1)
                .ok_or_else(|| de::Error::custom("native V2 array length overflow"))?;
            if matches!(value, Atom::Other) {
                all_bytes = false;
                other += 1;
                if other > REQUEST_FIELDS {
                    return Err(de::Error::custom(
                        "native V2 complex array exceeds closed shape",
                    ));
                }
            }
        }
        if all_bytes {
            self.0.payload = self.0.payload.max(count);
        }
        Ok(Atom::Other)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Atom, A::Error> {
        self.0.container()?;
        while map.next_key::<Field>()?.is_some() {
            self.0.field()?;
            map.next_value_seed(Scan(self.0))?;
        }
        Ok(Atom::Other)
    }
}

struct Request(Shape);
impl<'de> Deserialize<'de> for Request {
    fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let mut body = Body::default();
        Scan(&mut body).deserialize(decoder)?;
        Ok(Self(Shape {
            requests: 1,
            payload: body.payload,
        }))
    }
}

struct Batch(Shape);
impl<'de> Deserialize<'de> for Batch {
    fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Requests;
        impl<'de> Visitor<'de> for Requests {
            type Value = Batch;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("the existing bounded V2 batch")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Batch, A::Error> {
                let mut shape = Shape::default();
                while shape.requests
                    < crate::consensus::types::MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS
                {
                    let Some(request) = sequence.next_element::<Request>()? else {
                        return Ok(Batch(shape));
                    };
                    shape.requests += 1;
                    shape.payload = shape.payload.max(request.0.payload);
                }
                // IgnoredAny does not allocate a request or recurse into an
                // owning model even for an adversarial 257th element.
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("native V2 batch exceeds original count"));
                }
                Ok(Batch(shape))
            }
        }
        decoder.deserialize_seq(Requests)
    }
}

// No recursive enum. A second Authorized variant is rejected before the full
// SessionMutationIntent decoder can allocate nested boxes.
// The roster wire owns only canonical numeric byte capsules plus one bounded
// authority key. Its complete capsule decoders separately bound eight members,
// descriptor/proof collections and protected bytes. The outer scanner bounds
// all fields before those constructors run; it never expands capsule contents.
#[derive(Deserialize)]
enum InnerIntent {
    AdvanceLogicalTime,
    CompareAndSet(Request),
    DeleteFenced(Request),
    RefreshTtl(Request),
    AcquireLease(Request),
    RenewLease(Request),
    ReleaseLease(Request),
    BindConsumerRequest(Request),
    ReadConsumerRecord(Request),
    FencedTransition(Request),
    ActivateFencedTransition { request: Request },
    ActivateFencedTransitionCapability(Request),
    ActivateProtectedRosterProfileV2(Request),
    RosterAdmission(Request),
    RosterAdmissionV2(Request),
    RosterTerminal(Request),
    RosterTerminalV2(Request),
    FencedTransitionV2(Request),
    ActivateFencedTransitionV2 { request: Request },
    FencedTransitionV2Batch(Batch),
}
impl InnerIntent {
    fn shape(self) -> Shape {
        match self {
            Self::AdvanceLogicalTime => Shape::default(),
            Self::CompareAndSet(value)
            | Self::DeleteFenced(value)
            | Self::RefreshTtl(value)
            | Self::AcquireLease(value)
            | Self::RenewLease(value)
            | Self::ReleaseLease(value)
            | Self::BindConsumerRequest(value)
            | Self::ReadConsumerRecord(value)
            | Self::FencedTransition(value)
            | Self::ActivateFencedTransition { request: value }
            | Self::ActivateFencedTransitionCapability(value)
            | Self::ActivateProtectedRosterProfileV2(value)
            | Self::RosterAdmission(value)
            | Self::RosterAdmissionV2(value)
            | Self::RosterTerminal(value)
            | Self::RosterTerminalV2(value)
            | Self::FencedTransitionV2(value)
            | Self::ActivateFencedTransitionV2 { request: value } => value.0,
            Self::FencedTransitionV2Batch(value) => value.0,
        }
    }
}
#[derive(Deserialize)]
enum Intent {
    AdvanceLogicalTime,
    MaintainFencedTransitionV2History(Request),
    CompareAndSet(Request),
    DeleteFenced(Request),
    RefreshTtl(Request),
    AcquireLease(Request),
    RenewLease(Request),
    ReleaseLease(Request),
    BindConsumerRequest(Request),
    ReadConsumerRecord(Request),
    FencedTransition(Request),
    ActivateFencedTransition { request: Request },
    ActivateFencedTransitionCapability(Request),
    ActivateProtectedRosterProfileV2(Request),
    FencedTransitionV2(Request),
    ActivateFencedTransitionV2 { request: Request },
    FencedTransitionV2Batch(Batch),
    Authorized { mutation: InnerIntent },
}
impl Intent {
    fn shape(self) -> Shape {
        match self {
            Self::AdvanceLogicalTime => Shape::default(),
            Self::MaintainFencedTransitionV2History(value) => value.0,
            Self::CompareAndSet(value)
            | Self::DeleteFenced(value)
            | Self::RefreshTtl(value)
            | Self::AcquireLease(value)
            | Self::RenewLease(value)
            | Self::ReleaseLease(value)
            | Self::BindConsumerRequest(value)
            | Self::ReadConsumerRecord(value)
            | Self::FencedTransition(value)
            | Self::ActivateFencedTransition { request: value }
            | Self::ActivateFencedTransitionCapability(value)
            | Self::ActivateProtectedRosterProfileV2(value)
            | Self::FencedTransitionV2(value)
            | Self::ActivateFencedTransitionV2 { request: value } => value.0,
            Self::FencedTransitionV2Batch(value) => value.0,
            Self::Authorized { mutation } => mutation.shape(),
        }
    }
}

// Membership sets/maps allocate only their distinct keys in the actual model.
// Preserve legacy duplicate-key and ignored-field behavior; bound five distinct
// voters in stack storage, rather than restricting raw duplicate occurrences.
#[derive(Default)]
pub(in crate::consensus::native::generation) struct Members {
    ids: [u64; 5],
    length: usize,
}
impl Members {
    fn insert<E: de::Error>(&mut self, id: u64) -> Result<(), E> {
        if self.ids[..self.length].contains(&id) {
            return Ok(());
        }
        if self.length == self.ids.len() {
            return Err(E::custom(
                "native fixed membership exceeds its distinct-node bound",
            ));
        }
        self.ids[self.length] = id;
        self.length += 1;
        Ok(())
    }
}
impl<'de> Deserialize<'de> for Members {
    fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Nodes;
        impl<'de> Visitor<'de> for Nodes {
            type Value = Members;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a fixed membership set")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Members, A::Error> {
                let mut members = Members::default();
                while let Some(id) = sequence.next_element::<u64>()? {
                    members.insert(id)?;
                }
                Ok(members)
            }
        }
        decoder.deserialize_seq(Nodes)
    }
}
struct Configs;
impl<'de> Deserialize<'de> for Configs {
    fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Groups;
        impl<'de> Visitor<'de> for Groups {
            type Value = Configs;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("one fixed membership group")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Configs, A::Error> {
                if sequence.next_element::<Members>()?.is_some()
                    && sequence.next_element::<IgnoredAny>()?.is_some()
                {
                    return Err(de::Error::custom(
                        "native fixed membership has joint groups",
                    ));
                }
                Ok(Configs)
            }
        }
        decoder.deserialize_seq(Groups)
    }
}
struct Nodes;
impl<'de> Deserialize<'de> for Nodes {
    fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Keys;
        impl<'de> Visitor<'de> for Keys {
            type Value = Nodes;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("fixed membership nodes")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Nodes, A::Error> {
                let mut members = Members::default();
                while let Some(id) = map.next_key::<u64>()? {
                    members.insert(id)?;
                    map.next_value::<IgnoredAny>()?;
                }
                Ok(Nodes)
            }
        }
        decoder.deserialize_map(Keys)
    }
}
#[derive(Deserialize)]
pub(in crate::consensus::native::generation) struct Membership {
    #[serde(rename = "configs")]
    _configs: Configs,
    #[serde(rename = "nodes")]
    _nodes: Nodes,
}
#[derive(Deserialize)]
struct Command {
    intent: Intent,
}
#[derive(Deserialize)]
enum Payload {
    Blank,
    Membership(Membership),
    Normal(Command),
}
#[derive(Deserialize)]
struct Log {
    payload: Payload,
}

pub(super) fn log_scratch(bytes: &[u8]) -> io::Result<usize> {
    if bytes.is_empty()
        || bytes.len() > crate::sqlite::consensus::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES
    {
        return Err(invalid("native generation raw log size invalid"));
    }
    let shape = {
        // serde_json's escaped-string scratch is the only growable preflight
        // buffer. Charge its old/new Vec growth before creating the parser.
        // IgnoredAny skips arbitrary legacy metadata without retaining it.
        let _memory = VerificationMemory::reserve(
            bytes
                .len()
                .checked_mul(3)
                .and_then(|bytes| bytes.checked_add(METADATA))
                .ok_or_else(|| invalid("native generation JSON preflight overflow"))?,
        )?;
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        let log = Log::deserialize(&mut decoder)
            .map_err(|_| invalid("native generation raw log shape invalid"))?;
        decoder
            .end()
            .map_err(|_| invalid("native generation raw log has trailing bytes"))?;
        match log.payload {
            Payload::Normal(command) => command.intent.shape(),
            Payload::Blank | Payload::Membership(_) => Shape::default(),
        }
    };
    // Same audited retained-model/canonical-encoding/envelope bound as trusted
    // readback, now reached only after independent arbitrary-byte shape proof.
    scratch::log_peak(bytes.len(), shape.requests, shape.payload)
}
