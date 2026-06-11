use super::RustGenerationError;
use crate::emit::CanonicalInput;

pub fn generate(_input: &CanonicalInput) -> Result<String, RustGenerationError> {
    Ok(r#"
use serde::Deserialize;

pub trait ExtractKey<K> {
    fn extract_key(&self) -> K;
}

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

pub fn deserialize_list<'de, K, V, D>(deserializer: D) -> Result<std::collections::BTreeMap<K, V>, D::Error>
where
    V: serde::Deserialize<'de> + ExtractKey<K>,
    K: Ord,
    D: serde::Deserializer<'de>,
{
    let vec = Vec::<V>::deserialize(deserializer)?;
    let mut map = std::collections::BTreeMap::new();
    for item in vec {
        map.insert(item.extract_key(), item);
    }
    Ok(map)
}

pub fn is_sequence_empty<T>(seq: &T) -> bool
where
    for<'a> &'a T: IntoIterator,
{
    seq.into_iter().next().is_none()
}
"#.to_string())
}
