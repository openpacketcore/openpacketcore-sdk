//! Cold header allocation admission. Raw headers keep the original 64KiB
//! bound. Stream the only variable nested collections before owning decoding:
//! fixed voter sets, membership configurations and snapshot strings. Unknown
//! fields are still rejected by the complete canonical header decoder.

use super::*;
use serde::de::{self, IgnoredAny, Visitor};
use std::fmt;

// Two contexts, each with fixed membership and one snapshot, plus complete
// raw/parser/canonical-buffer growth. This is one reservation in the existing
// process budget, held as long as any decoded header allocation is alive.
const MEMORY: usize = 16 * MAX_HEADER;

struct Name;
impl<'de> Deserialize<'de> for Name {
    fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Bounded;
        impl Visitor<'_> for Bounded {
            type Value = Name;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded native snapshot string")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Name, E> {
                if value.len() > 256 {
                    return Err(E::custom("native generation snapshot string exceeds bound"));
                }
                Ok(Name)
            }
        }
        decoder.deserialize_str(Bounded)
    }
}

#[derive(Deserialize)]
struct Stored {
    #[serde(rename = "membership")]
    _membership: decode::json::Membership,
}
#[derive(Deserialize)]
struct Snapshot {
    #[serde(rename = "last_membership")]
    _membership: Stored,
    #[serde(rename = "snapshot_id")]
    _id: Name,
}
#[derive(Deserialize)]
struct Frontiers {
    #[serde(rename = "membership")]
    _membership: Stored,
    #[serde(rename = "current_snapshot")]
    _snapshot: Option<(Snapshot, Name, IgnoredAny, IgnoredAny)>,
}
#[derive(Deserialize)]
struct Business {
    #[serde(rename = "members")]
    _members: decode::json::Members,
    #[serde(rename = "frontiers")]
    _frontiers: Frontiers,
}
#[derive(Deserialize)]
struct Shape {
    #[serde(rename = "business")]
    _business: Business,
}
#[derive(Deserialize)]
struct BaseShape {
    #[serde(rename = "context")]
    _context: Shape,
}
#[derive(Deserialize)]
struct DeltaShape {
    #[serde(rename = "before")]
    _before: Shape,
    #[serde(rename = "after")]
    _after: Shape,
}

pub(super) struct Loaded<T> {
    pub(super) value: T,
    _memory: VerificationMemory,
}

fn read<T: serde::de::DeserializeOwned + Serialize, S: serde::de::DeserializeOwned>(
    reader: &mut dyn Read,
) -> io::Result<Loaded<T>> {
    let memory = VerificationMemory::reserve(MEMORY)?;
    let input = read_bytes(reader, MAX_HEADER)?;
    {
        let mut decoder = serde_json::Deserializer::from_slice(input.bytes());
        let _shape = S::deserialize(&mut decoder)
            .map_err(|_| invalid("native generation cold header allocation shape invalid"))?;
        decoder
            .end()
            .map_err(|_| invalid("native generation cold header has trailing bytes"))?;
    }
    let value: T = serde_json::from_slice(input.bytes())
        .map_err(|_| invalid("native generation cold header invalid"))?;
    let canonical = encode_header(&value)?;
    if canonical.as_slice() != input.bytes() {
        return Err(invalid("native generation cold header is not canonical"));
    }
    Ok(Loaded {
        value,
        _memory: memory,
    })
}

pub(super) fn base(reader: &mut dyn Read) -> io::Result<Loaded<BaseHeader>> {
    read::<BaseHeader, BaseShape>(reader)
}
pub(super) fn delta(reader: &mut dyn Read) -> io::Result<Loaded<Header>> {
    read::<Header, DeltaShape>(reader)
}
