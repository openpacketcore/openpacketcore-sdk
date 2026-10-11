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

/// A keyed YANG list whose iteration and equality include insertion order.
///
/// New keys append, removal preserves the remaining order, and updates through
/// `get_mut` or `entry` keep an existing key in place. Lookups are linear; the
/// SDK-owned representation needs no additional generated-code dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserOrderedMap<K, V> {
    entries: Vec<(K, V)>,
}

impl<K, V> Default for UserOrderedMap<K, V> {
    fn default() -> Self {
        Self { entries: Vec::new() }
    }
}

/// A duplicate insertion leaves the existing row and its position unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateListKey;

impl std::fmt::Display for DuplicateListKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(DUPLICATE_LIST_KEY_ERROR)
    }
}

impl std::error::Error for DuplicateListKey {}

impl<K, V> UserOrderedMap<K, V> {
    /// Creates an empty user-ordered list.
    pub fn new() -> Self { Self::default() }
    /// Returns the number of rows.
    pub fn len(&self) -> usize { self.entries.len() }
    /// Returns whether the list has no rows.
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    /// Removes all rows.
    pub fn clear(&mut self) { self.entries.clear(); }
    /// Iterates over keys in user order.
    pub fn keys(&self) -> impl ExactSizeIterator<Item = &K> {
        self.entries.iter().map(|(key, _)| key)
    }
    /// Iterates over rows in user order.
    pub fn values(&self) -> impl ExactSizeIterator<Item = &V> {
        self.entries.iter().map(|(_, value)| value)
    }
    /// Mutably iterates over rows without changing their positions.
    pub fn values_mut(&mut self) -> impl ExactSizeIterator<Item = &mut V> {
        self.entries.iter_mut().map(|(_, value)| value)
    }
    /// Looks up a row by its key, including a borrowed key such as `str`.
    pub fn get<Q: ?Sized + PartialEq>(&self, key: &Q) -> Option<&V>
    where K: std::borrow::Borrow<Q> {
        self.entries.iter().find(|(k, _)| k.borrow() == key).map(|(_, v)| v)
    }
    /// Looks up a row for an in-place update.
    pub fn get_mut<Q: ?Sized + PartialEq>(&mut self, key: &Q) -> Option<&mut V>
    where K: std::borrow::Borrow<Q> {
        self.entries.iter_mut().find(|(k, _)| k.borrow() == key).map(|(_, v)| v)
    }
    /// Reports whether a key is present.
    pub fn contains_key<Q: ?Sized + PartialEq>(&self, key: &Q) -> bool
    where K: std::borrow::Borrow<Q> {
        self.get(key).is_some()
    }
    /// Removes one row while retaining the order of all remaining rows.
    pub fn remove<Q: ?Sized + PartialEq>(&mut self, key: &Q) -> Option<V>
    where K: std::borrow::Borrow<Q> {
        let index = self.entries.iter().position(|(k, _)| k.borrow() == key)?;
        Some(self.entries.remove(index).1)
    }
}

impl<K: PartialEq, V> UserOrderedMap<K, V> {
    /// Adds a new row at the end, refusing to overwrite a duplicate key.
    pub fn insert(&mut self, key: K, value: V) -> Result<(), DuplicateListKey> {
        if self.contains_key(&key) {
            return Err(DuplicateListKey);
        }
        self.entries.push((key, value));
        Ok(())
    }

    /// Explicitly updates an existing row in place or appends a new row.
    pub fn entry(&mut self, key: K) -> UserOrderedEntry<'_, K, V> {
        UserOrderedEntry { map: self, key }
    }
}

/// An explicit update-or-append operation on a user-ordered list.
pub struct UserOrderedEntry<'a, K, V> {
    map: &'a mut UserOrderedMap<K, V>,
    key: K,
}

impl<'a, K: PartialEq, V: Default> UserOrderedEntry<'a, K, V> {
    /// Returns the existing row in place, or appends and returns a default row.
    pub fn or_default(self) -> &'a mut V {
        let index = self.map.entries.iter().position(|(key, _)| *key == self.key)
            .unwrap_or_else(|| {
                self.map.entries.push((self.key, V::default()));
                self.map.entries.len() - 1
            });
        &mut self.map.entries[index].1
    }
}

impl<K, V> IntoIterator for UserOrderedMap<K, V> {
    type Item = (K, V);
    type IntoIter = std::vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter { self.entries.into_iter() }
}

impl<'a, K, V> IntoIterator for &'a UserOrderedMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = std::iter::Map<std::slice::Iter<'a, (K, V)>, fn(&'a (K, V)) -> Self::Item>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter().map(|(key, value)| (key, value))
    }
}

impl<K, V: serde::Serialize> serde::Serialize for UserOrderedMap<K, V> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for value in self.values() { seq.serialize_element(value)?; }
        seq.end()
    }
}

impl<'de, K: PartialEq, V: serde::Deserialize<'de> + ExtractKey<K>> serde::Deserialize<'de>
    for UserOrderedMap<K, V>
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let rows = Vec::<V>::deserialize(deserializer)?;
        let mut map = Self::new();
        for row in rows {
            let key = row.extract_key()
                .ok_or_else(|| serde::de::Error::custom(MISSING_LIST_KEY_ERROR))?;
            map.insert(key, row).map_err(serde::de::Error::custom)?;
        }
        Ok(map)
    }
}

/// Stable, value-free error for repeated user-ordered leaf-list values.
pub const DUPLICATE_LEAF_LIST_VALUE_ERROR: &str = "leaf-list contains a duplicate value";

/// Checks typed equality without requiring `Ord` for every YANG scalar.
pub fn has_duplicate_values<T: PartialEq>(values: &[T]) -> bool {
    values.iter().enumerate().any(|(index, value)| values[..index].contains(value))
}

/// Serializes leaf-list values in order, refusing an invalid typed list.
pub fn serialize_unique_leaf_list<T, S>(values: &[T], serializer: S) -> Result<S::Ok, S::Error>
where
    T: serde::Serialize + PartialEq,
    S: serde::Serializer,
{
    if has_duplicate_values(values) {
        return Err(serde::ser::Error::custom(DUPLICATE_LEAF_LIST_VALUE_ERROR));
    }
    serde::Serialize::serialize(values, serializer)
}

/// Deserializes leaf-list values in order and rejects duplicates.
pub fn deserialize_unique_leaf_list<'de, T, M, D>(deserializer: D) -> Result<M, D::Error>
where
    T: serde::Deserialize<'de> + PartialEq,
    M: From<Vec<T>>,
    D: serde::Deserializer<'de>,
{
    let values = Vec::<T>::deserialize(deserializer)?;
    if has_duplicate_values(&values) {
        return Err(serde::de::Error::custom(DUPLICATE_LEAF_LIST_VALUE_ERROR));
    }
    Ok(values.into())
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
