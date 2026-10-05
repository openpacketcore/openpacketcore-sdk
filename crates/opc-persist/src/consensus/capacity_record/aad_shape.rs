//! Scalar shape admission before the internally tagged canonical AAD decoder.
//! This pass retains no field strings or arbitrary JSON container tree.

use crate::PersistError;
use opc_crypto::CONFIG_CAPACITY_V1_AAD_BYTES;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;

struct Text<const MAX: usize>;

// The canonical envelope uses objects. Serde's derived structs also accept
// positional sequences; do not admit that alternate container shape here.
struct Object<T>(std::marker::PhantomData<T>);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
            type Value = Object<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an AAD object")
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                T::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(Object(std::marker::PhantomData))
            }
        }
        deserializer.deserialize_map(ObjectVisitor::<T>(std::marker::PhantomData))
    }
}

// An explicit field deserializer suppresses the derived missing Option default:
// null is permitted, omission is not.
fn required_parent<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Text<CONFIG_CAPACITY_V1_AAD_BYTES>>, D::Error> {
    Option::deserialize(deserializer)
}

impl<'de, const MAX: usize> Deserialize<'de> for Text<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TextVisitor<const MAX: usize>;
        impl<const MAX: usize> Visitor<'_> for TextVisitor<MAX> {
            type Value = Text<MAX>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded scalar configuration metadata")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.len() > MAX {
                    return Err(E::custom("configuration metadata exceeds capacity"));
                }
                Ok(Text)
            }
        }
        deserializer.deserialize_str(TextVisitor::<MAX>)
    }
}

struct ConfigOnly;
impl<'de> Deserialize<'de> for ConfigOnly {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ConfigVisitor;
        impl Visitor<'_> for ConfigVisitor {
            type Value = ConfigOnly;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("configuration metadata")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value != "config" {
                    return Err(E::custom("configuration metadata kind mismatch"));
                }
                Ok(ConfigOnly)
            }
        }
        deserializer.deserialize_str(ConfigVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AadShape {
    #[serde(rename = "tenant")]
    _tenant: Text<CONFIG_CAPACITY_V1_AAD_BYTES>,
    #[serde(rename = "purpose")]
    _purpose: ConfigOnly,
    #[serde(rename = "version")]
    _version: u64,
    #[serde(rename = "key_id")]
    _key_id: Text<512>,
    #[serde(rename = "metadata")]
    _metadata: Object<MetadataShape>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataShape {
    #[serde(rename = "kind")]
    _kind: ConfigOnly,
    #[serde(rename = "tx_id")]
    _tx_id: Text<CONFIG_CAPACITY_V1_AAD_BYTES>,
    #[serde(rename = "parent_tx_id", deserialize_with = "required_parent")]
    _parent_tx_id: Option<Text<CONFIG_CAPACITY_V1_AAD_BYTES>>,
    #[serde(rename = "committed_at")]
    _committed_at: Text<CONFIG_CAPACITY_V1_AAD_BYTES>,
    #[serde(rename = "principal")]
    _principal: Text<CONFIG_CAPACITY_V1_AAD_BYTES>,
    #[serde(rename = "schema_digest")]
    _schema_digest: Text<CONFIG_CAPACITY_V1_AAD_BYTES>,
    #[serde(rename = "store_kind")]
    _store_kind: Text<CONFIG_CAPACITY_V1_AAD_BYTES>,
}

pub(super) fn preflight(bytes: &[u8]) -> Result<(), PersistError> {
    if bytes.len() > CONFIG_CAPACITY_V1_AAD_BYTES {
        return Err(PersistError::corrupt_blob());
    }
    serde_json::from_slice::<Object<AadShape>>(bytes)
        .map(|_| ())
        .map_err(|_| PersistError::corrupt_blob())
}

#[cfg(test)]
mod tests;
