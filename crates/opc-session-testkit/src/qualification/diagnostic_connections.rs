//! Decode peer indexes after the internally tagged reply buffers JSON keys.

use std::{collections::BTreeMap, fmt};

use serde::de::{Error, MapAccess, Visitor};
use serde::Deserializer;
use serde_json::Value;

pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<usize, Value>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Connections;

    impl<'de> Visitor<'de> for Connections {
        type Value = BTreeMap<usize, Value>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map of canonical peer indexes to connection diagnostics")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut connections = BTreeMap::new();
            // JSON object keys are strings. Serde's internally tagged enum
            // buffer no longer has serde_json's integer-key adapter, so decode
            // exactly the decimal keys emitted by BTreeMap<usize, _> ourselves.
            while let Some(key) = map.next_key::<String>()? {
                let index = key
                    .parse::<usize>()
                    .map_err(|_| M::Error::custom("invalid diagnostic peer index"))?;
                if index.to_string() != key {
                    return Err(M::Error::custom("noncanonical diagnostic peer index"));
                }
                let value = map.next_value()?;
                if connections.insert(index, value).is_some() {
                    return Err(M::Error::custom("duplicate diagnostic peer index"));
                }
            }
            Ok(connections)
        }
    }

    deserializer.deserialize_map(Connections)
}
