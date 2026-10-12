use super::RustGenerationError;
use crate::emit::CanonicalInput;

pub fn generate(input: &CanonicalInput) -> Result<String, RustGenerationError> {
    let mut output = r#"
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

"#
    .to_string();
    if super::has_user_ordered_collections(input) {
        output.push_str(r#"/// A keyed YANG list whose iteration and equality include insertion order.
///
/// New keys append, removal preserves the remaining order, and updates through
/// `get_mut` or `entry` keep an existing key in place. The key index gives
/// expected O(1) lookup and append, and amortized expected O(1) removal.
/// Removed slots are compacted once they outnumber live rows. Construction,
/// unchanged-list diff, bulk deletion and redaction are expected O(n);
/// iteration is O(n). The SDK-owned type needs no additional dependency.
/// Indexed operations require keys implementing `Clone + Eq + Hash`.
#[derive(Clone)]
pub struct UserOrderedMap<K, V> {
    entries: Vec<Option<(K, V)>>,
    positions: std::collections::HashMap<K, usize>,
}

impl<K, V> Default for UserOrderedMap<K, V> {
    fn default() -> Self {
        Self { entries: Vec::new(), positions: std::collections::HashMap::new() }
    }
}

impl<K: PartialEq, V: PartialEq> PartialEq for UserOrderedMap<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len()
            && self.entries.iter().flatten().eq(other.entries.iter().flatten())
    }
}

impl<K: Eq, V: Eq> Eq for UserOrderedMap<K, V> {}

impl<K: std::fmt::Debug, V: std::fmt::Debug> std::fmt::Debug for UserOrderedMap<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map().entries(self).finish()
    }
}

/// An exact-size iterator over live rows in user order.
#[derive(Clone, Debug)]
pub struct UserOrderedIter<I> {
    inner: I,
    remaining: usize,
}

impl<I: Iterator> Iterator for UserOrderedIter<I> {
    type Item = I::Item;
    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next()?;
        self.remaining -= 1;
        Some(item)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<I: Iterator> ExactSizeIterator for UserOrderedIter<I> {}

impl<I: DoubleEndedIterator> DoubleEndedIterator for UserOrderedIter<I> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let item = self.inner.next_back()?;
        self.remaining -= 1;
        Some(item)
    }
}

impl<I: std::iter::FusedIterator> std::iter::FusedIterator for UserOrderedIter<I> {}

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
    pub fn len(&self) -> usize { self.positions.len() }
    /// Returns whether the list has no rows.
    pub fn is_empty(&self) -> bool { self.positions.is_empty() }
    /// Removes all rows.
    pub fn clear(&mut self) { self.entries.clear(); self.positions.clear(); }
    /// Iterates over keys in user order.
    pub fn keys(&self) -> impl ExactSizeIterator<Item = &K> {
        UserOrderedIter {
            inner: self.entries.iter().filter_map(|entry| entry.as_ref().map(|(key, _)| key)),
            remaining: self.len(),
        }
    }
    /// Iterates over rows in user order.
    pub fn values(&self) -> impl ExactSizeIterator<Item = &V> {
        UserOrderedIter {
            inner: self.entries.iter().filter_map(|entry| entry.as_ref().map(|(_, value)| value)),
            remaining: self.len(),
        }
    }
    /// Mutably iterates over rows without changing their positions.
    pub fn values_mut(&mut self) -> impl ExactSizeIterator<Item = &mut V> {
        let remaining = self.len();
        UserOrderedIter {
            inner: self.entries.iter_mut().filter_map(|entry| entry.as_mut().map(|(_, value)| value)),
            remaining,
        }
    }
}

impl<K: Eq + std::hash::Hash, V> UserOrderedMap<K, V> {
    /// Looks up a row by its key, including a borrowed key such as `str`.
    pub fn get<Q: ?Sized + Eq + std::hash::Hash>(&self, key: &Q) -> Option<&V>
    where K: std::borrow::Borrow<Q> {
        let index = *self.positions.get(key)?;
        self.entries[index].as_ref().map(|(_, value)| value)
    }
    /// Looks up a row for an in-place update.
    pub fn get_mut<Q: ?Sized + Eq + std::hash::Hash>(&mut self, key: &Q) -> Option<&mut V>
    where K: std::borrow::Borrow<Q> {
        let index = *self.positions.get(key)?;
        self.entries[index].as_mut().map(|(_, value)| value)
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
        let (_, value) = self.entries[index].take().expect("indexed row is live");
        if self.entries.len() - self.len() > self.len() {
            self.entries.retain(Option::is_some);
            for (position, entry) in self.entries.iter().enumerate() {
                let (key, _) = entry.as_ref().expect("compacted row is live");
                *self.positions.get_mut::<K>(key).expect("live row is indexed") = position;
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
        self.entries.push(Some((key, value)));
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
                self.map.entries.push(Some((self.key, V::default())));
                position
            });
        &mut self.map.entries[index].as_mut().expect("indexed row is live").1
    }
}

impl<K, V> IntoIterator for UserOrderedMap<K, V> {
    type Item = (K, V);
    type IntoIter = UserOrderedIter<std::iter::Flatten<std::vec::IntoIter<Option<(K, V)>>>>;
    fn into_iter(self) -> Self::IntoIter {
        let remaining = self.len();
        UserOrderedIter { inner: self.entries.into_iter().flatten(), remaining }
    }
}

impl<'a, K, V> IntoIterator for &'a UserOrderedMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = UserOrderedIter<std::iter::FilterMap<
        std::slice::Iter<'a, Option<(K, V)>>,
        fn(&'a Option<(K, V)>) -> Option<Self::Item>,
    >>;
    fn into_iter(self) -> Self::IntoIter {
        UserOrderedIter {
            inner: self.entries.iter().filter_map(|entry| entry.as_ref().map(|(key, value)| (key, value))),
            remaining: self.len(),
        }
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

"#);
    }
    output.push_str(r#"pub fn serialize_list<K, V, S>(map: &std::collections::BTreeMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
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
"#);
    Ok(output)
}
