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
/// `get_mut` or `entry` keep an existing key in place. The key index gives
/// expected O(1) lookup and append. Construction, unchanged-list diff and
/// redaction are expected O(n); iteration and order-preserving removal are
/// O(n). The SDK-owned type needs no additional generated-code dependency.
/// Indexed operations require keys implementing `Clone + Eq + Hash`.
#[derive(Debug, Clone)]
pub struct UserOrderedMap<K, V> {
    entries: Vec<(K, V)>,
    positions: std::collections::HashMap<K, usize>,
}

impl<K, V> Default for UserOrderedMap<K, V> {
    fn default() -> Self {
        Self { entries: Vec::new(), positions: std::collections::HashMap::new() }
    }
}

impl<K: PartialEq, V: PartialEq> PartialEq for UserOrderedMap<K, V> {
    fn eq(&self, other: &Self) -> bool { self.entries == other.entries }
}

impl<K: Eq, V: Eq> Eq for UserOrderedMap<K, V> {}

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
    pub fn clear(&mut self) { self.entries.clear(); self.positions.clear(); }
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
}

impl<K: Eq + std::hash::Hash, V> UserOrderedMap<K, V> {
    /// Looks up a row by its key, including a borrowed key such as `str`.
    pub fn get<Q: ?Sized + Eq + std::hash::Hash>(&self, key: &Q) -> Option<&V>
    where K: std::borrow::Borrow<Q> {
        self.positions.get(key).map(|&index| &self.entries[index].1)
    }
    /// Looks up a row for an in-place update.
    pub fn get_mut<Q: ?Sized + Eq + std::hash::Hash>(&mut self, key: &Q) -> Option<&mut V>
    where K: std::borrow::Borrow<Q> {
        let index = *self.positions.get(key)?;
        Some(&mut self.entries[index].1)
    }
    /// Reports whether a key is present.
    pub fn contains_key<Q: ?Sized + Eq + std::hash::Hash>(&self, key: &Q) -> bool
    where K: std::borrow::Borrow<Q> {
        self.positions.contains_key(key)
    }
    /// Removes one row while retaining the order of all remaining rows.
    pub fn remove<Q: ?Sized + Eq + std::hash::Hash>(&mut self, key: &Q) -> Option<V>
    where K: std::borrow::Borrow<Q> {
        let index = self.positions.remove(key)?;
        let (_, value) = self.entries.remove(index);
        for (position, (key, _)) in self.entries.iter().enumerate().skip(index) {
            if let Some(stored_position) = self.positions.get_mut::<K>(key) {
                *stored_position = position;
            }
        }
        Some(value)
    }
}

impl<K: Clone + Eq + std::hash::Hash, V> UserOrderedMap<K, V> {
    /// Adds a new row at the end, refusing to overwrite a duplicate key.
    pub fn insert(&mut self, key: K, value: V) -> Result<(), DuplicateListKey> {
        if self.contains_key(&key) {
            return Err(DuplicateListKey);
        }
        self.positions.insert(key.clone(), self.entries.len());
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

impl<'a, K: Clone + Eq + std::hash::Hash, V: Default> UserOrderedEntry<'a, K, V> {
    /// Returns the existing row in place, or appends and returns a default row.
    pub fn or_default(self) -> &'a mut V {
        let index = self.map.positions.get(&self.key).copied()
            .unwrap_or_else(|| {
                let position = self.map.entries.len();
                self.map.positions.insert(self.key.clone(), position);
                self.map.entries.push((self.key, V::default()));
                position
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

impl<'de, K: Clone + Eq + std::hash::Hash, V: serde::Deserialize<'de> + ExtractKey<K>> serde::Deserialize<'de>
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

/// Checks typed equality in expected O(n), including scalars without `Eq`.
/// Hash collisions are resolved by equality, never treated as duplicates.
pub fn has_duplicate_values<T: PartialEq + std::hash::Hash>(values: &[T]) -> bool {
    let hash_state = std::collections::hash_map::RandomState::new();
    let mut buckets: std::collections::HashMap<u64, Vec<&T>> =
        std::collections::HashMap::with_capacity(values.len());
    for value in values {
        let hash = std::hash::BuildHasher::hash_one(&hash_state, value);
        let bucket = buckets.entry(hash).or_default();
        if bucket.contains(&value) { return true; }
        bucket.push(value);
    }
    false
}

/// Serializes leaf-list values in order, refusing an invalid typed list.
pub fn serialize_unique_leaf_list<T, S>(values: &[T], serializer: S) -> Result<S::Ok, S::Error>
where
    T: serde::Serialize + PartialEq + std::hash::Hash,
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
    T: serde::Deserialize<'de> + PartialEq + std::hash::Hash,
    M: From<Vec<T>>,
    D: serde::Deserializer<'de>,
{
    let values = Vec::<T>::deserialize(deserializer)?;
    if has_duplicate_values(&values) {
        return Err(serde::de::Error::custom(DUPLICATE_LEAF_LIST_VALUE_ERROR));
    }
    Ok(values.into())
}

/// Applies the same uniqueness check without removing the secret wrapper.
pub fn serialize_unique_secret_leaf_list<T, S>(
    values: &super::types::SecretLeaf<Vec<T>>, serializer: S,
) -> Result<S::Ok, S::Error>
where
    T: serde::Serialize + PartialEq + std::hash::Hash,
    S: serde::Serializer,
{
    serialize_unique_leaf_list(values.get(), serializer)
}

/// Loads unique secret values while retaining their redaction wrapper.
pub fn deserialize_unique_secret_leaf_list<'de, T, D>(deserializer: D)
    -> Result<super::types::SecretLeaf<Vec<T>>, D::Error>
where
    T: serde::Deserialize<'de> + PartialEq + std::hash::Hash,
    D: serde::Deserializer<'de>,
{
    let values: Vec<T> = deserialize_unique_leaf_list(deserializer)?;
    Ok(super::types::SecretLeaf::new(values))
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
