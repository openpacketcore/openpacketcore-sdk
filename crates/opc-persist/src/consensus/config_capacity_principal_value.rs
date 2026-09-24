//! Classify reserved principal values without retaining rejected containers.
//!
//! Scalars keep the original `serde_json::Value` representation. Arrays and
//! ordinary objects are fully validated, then represented by empty containers.
//! Those containers are invalid for every reserved field. Validation still uses
//! `deserialize_any`: replacing it with `IgnoredAny` changes numeric-overflow
//! errors and the durable parser's legacy fallback.

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::fmt;
use std::sync::OnceLock;

pub(super) struct PrincipalValueSeed {
    retain_scalar: bool,
}

impl PrincipalValueSeed {
    pub(super) fn retained() -> Self {
        Self {
            retain_scalar: true,
        }
    }

    fn discarded() -> Self {
        Self {
            retain_scalar: false,
        }
    }
}

impl<'de> DeserializeSeed<'de> for PrincipalValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for PrincipalValueSeed {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_i128<E>(self, value: i128) -> Result<Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::deserialize(de::value::I128Deserializer::new(value)).map(Value::Number)
    }

    fn visit_u128<E>(self, value: u128) -> Result<Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::deserialize(de::value::U128Deserializer::new(value)).map(Value::Number)
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E>
    where
        E: de::Error,
    {
        Ok(if self.retain_scalar {
            Value::String(value.to_owned())
        } else {
            Value::Null
        })
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(if self.retain_scalar {
            Value::String(value)
        } else {
            Value::Null
        })
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut values: A) -> Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while values
            .next_element_seed(PrincipalValueSeed::discarded())?
            .is_some()
        {}
        Ok(Value::Array(Vec::new()))
    }

    fn visit_map<A>(self, mut values: A) -> Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let Some(first_key) = values.next_key::<String>()? else {
            return Ok(Value::Object(serde_json::Map::new()));
        };
        // Value recognizes these tokens only in the first key position, and
        // only when their serde_json feature is enabled. Query the linked
        // implementation once so dependency feature unification is preserved.
        if first_key == "$serde_json::private::RawValue" && raw_value_token_enabled() {
            drop(first_key);
            return values.next_value_seed(RawPrincipalValueSeed(self));
        }
        if first_key == "$serde_json::private::Number" && number_token_enabled() {
            return Value::deserialize(de::value::MapAccessDeserializer::new(FirstKeyMap {
                first_key: Some(first_key),
                values,
            }));
        }
        drop(first_key);
        values.next_value_seed(PrincipalValueSeed::discarded())?;
        while values.next_key::<String>()?.is_some() {
            values.next_value_seed(PrincipalValueSeed::discarded())?;
        }
        Ok(Value::Object(serde_json::Map::new()))
    }
}

fn raw_value_token_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        matches!(
            serde_json::from_str::<Value>(r#"{"$serde_json::private::RawValue":"null"}"#),
            Ok(Value::Null)
        )
    })
}

fn number_token_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        matches!(
            serde_json::from_str::<Value>(r#"{"$serde_json::private::Number":"0"}"#),
            Ok(Value::Number(_))
        )
    })
}

// Replaying the first key lets the original Value implementation handle its
// feature-dependent number representation, including invalid numeric strings.
// This branch is used only when it is known to produce a scalar Number.
struct FirstKeyMap<A> {
    first_key: Option<String>,
    values: A,
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for FirstKeyMap<A> {
    type Error = A::Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, A::Error>
    where
        K: DeserializeSeed<'de>,
    {
        if let Some(key) = self.first_key.take() {
            return seed
                .deserialize(de::value::StringDeserializer::new(key))
                .map(Some);
        }
        self.values.next_key_seed(seed)
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, A::Error>
    where
        V: DeserializeSeed<'de>,
    {
        self.values.next_value_seed(seed)
    }
}

// Parse the embedded JSON while borrowing the deserializer's string. Do not
// create Value's second owned raw-string copy or rebuild an embedded container.
struct RawPrincipalValueSeed(PrincipalValueSeed);

impl<'de> DeserializeSeed<'de> for RawPrincipalValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(self)
    }
}

impl<'de> Visitor<'de> for RawPrincipalValueSeed {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a raw JSON string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E>
    where
        E: de::Error,
    {
        let mut deserializer = serde_json::Deserializer::from_str(value);
        let value = self
            .0
            .deserialize(&mut deserializer)
            .map_err(|_| E::custom("invalid config metadata JSON"))?;
        deserializer
            .end()
            .map_err(|_| E::custom("invalid config metadata JSON"))?;
        Ok(value)
    }
}
