use super::RustGenerationError;
use crate::emit::CanonicalInput;

pub fn generate(_input: &CanonicalInput) -> Result<String, RustGenerationError> {
    Ok(r#"
use serde::Deserialize;

/// Extracts a complete key from a generated keyed-list row.
pub trait ExtractKey<K> {
    /// Returns `None` when any required YANG key leaf is absent.
    fn extract_key(&self) -> Option<K>;
}

/// Stable, value-free error returned for an incomplete keyed-list row.
pub const MISSING_LIST_KEY_ERROR: &str = "keyed-list entry is missing a required key leaf";
/// Stable, value-free error returned for a duplicate keyed-list row.
pub const DUPLICATE_LIST_KEY_ERROR: &str = "keyed-list contains a duplicate key";

pub fn serialize_list<K, V, S>(map: &std::collections::BTreeMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
where
    V: serde::Serialize,
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let mut seq = serializer.serialize_seq(Some(map.len()))?;
    for value in map.values() {
        seq.serialize_element(value)?;
    }
    seq.end()
}

pub fn deserialize_list<'de, K, V, M, D>(deserializer: D) -> Result<M, D::Error>
where
    V: serde::Deserialize<'de> + ExtractKey<K>,
    K: Ord,
    M: From<std::collections::BTreeMap<K, V>>,
    D: serde::Deserializer<'de>,
{
    let vec = Vec::<V>::deserialize(deserializer)?;
    let mut map = std::collections::BTreeMap::new();
    for item in vec {
        let key = item
            .extract_key()
            .ok_or_else(|| serde::de::Error::custom(MISSING_LIST_KEY_ERROR))?;
        if map.insert(key, item).is_some() {
            return Err(serde::de::Error::custom(DUPLICATE_LIST_KEY_ERROR));
        }
    }
    Ok(map.into())
}

pub fn is_sequence_empty<T>(seq: &T) -> bool
where
    for<'a> &'a T: IntoIterator,
{
    seq.into_iter().next().is_none()
}
"#.to_string())
}
