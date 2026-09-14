//! Immutable business row indexes with pointer-sized trie entries. A full
//! key and its published row share one allocation, instead of reserving their
//! inline widths in every occupied or empty HAMT node slot. Captures retain
//! the same roots, keys and SharedRow revisions. Hashes select a bucket only;
//! every lookup still compares the complete original key.

use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Borrow;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

struct Stored<K, V>(Arc<(K, V)>);

impl<K, V> Clone for Stored<K, V> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<K, V> Borrow<K> for Stored<K, V> {
    fn borrow(&self) -> &K {
        &self.0 .0
    }
}

impl<K: Hash, V> Hash for Stored<K, V> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0 .0.hash(state);
    }
}

impl<K: PartialEq, V> PartialEq for Stored<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.0 .0 == other.0 .0
    }
}
impl<K: Eq, V> Eq for Stored<K, V> {}

impl<K, V: Clone> Stored<K, V> {
    fn into_value(self) -> V {
        match Arc::try_unwrap(self.0) {
            Ok((_, value)) => value,
            Err(shared) => shared.1.clone(),
        }
    }
}

pub(super) struct RowMap<K, V> {
    // The value belongs to the immutable entry. imbl replaces the complete
    // entry on insert, so equal keys publish the new value without touching
    // any entry still held by a capture. Unit occupies no trie value space.
    rows: imbl::HashMap<Stored<K, V>, ()>,
}

impl<K, V> Clone for RowMap<K, V> {
    fn clone(&self) -> Self {
        Self {
            rows: self.rows.clone(),
        }
    }
}

impl<K, V> Default for RowMap<K, V> {
    fn default() -> Self {
        Self {
            rows: imbl::HashMap::new(),
        }
    }
}

impl<K, V> RowMap<K, V> {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn len(&self) -> usize {
        self.rows.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub(super) fn iter(&self) -> Iter<'_, K, V> {
        Iter {
            inner: self.rows.iter(),
        }
    }

    #[cfg(test)]
    pub(super) fn values(&self) -> impl Iterator<Item = &V> {
        self.iter().map(|(_, value)| value)
    }

    #[cfg(test)]
    pub(super) fn clear(&mut self) {
        self.rows.clear();
    }

    #[cfg(test)]
    pub(super) fn keys(&self) -> impl Iterator<Item = &K> {
        self.iter().map(|(key, _)| key)
    }
}

impl<K: Hash + Eq, V> RowMap<K, V> {
    pub(super) fn get(&self, key: &K) -> Option<&V> {
        self.rows.get_key_value(key).map(|(row, ())| &row.0 .1)
    }

    pub(super) fn contains_key(&self, key: &K) -> bool {
        self.rows.contains_key(key)
    }
}

impl<K: Hash + Eq, V: Clone> RowMap<K, V> {
    pub(super) fn insert(&mut self, key: K, value: V) -> Option<V> {
        let previous = self.get(&key).cloned();
        self.rows.insert(Stored(Arc::new((key, value))), ());
        previous
    }

    pub(super) fn remove(&mut self, key: &K) -> Option<V> {
        self.rows
            .remove_with_key(key)
            .map(|(row, ())| row.into_value())
    }
}

pub(super) struct Iter<'a, K, V> {
    inner: imbl::hashmap::Iter<'a, Stored<K, V>, (), imbl::shared_ptr::DefaultSharedPtr>,
}

impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(row, ())| (&row.0 .0, &row.0 .1))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<K, V> ExactSizeIterator for Iter<'_, K, V> {}

impl<'a, K, V> IntoIterator for &'a RowMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<K: Serialize, V: Serialize> Serialize for RowMap<K, V> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Identical map vocabulary and full fields as the previous imbl map;
        // pointers, trie nodes and process revisions are never serialized.
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (key, value) in self {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl<'de, K: Deserialize<'de> + Hash + Eq, V: Deserialize<'de> + Clone> Deserialize<'de>
    for RowMap<K, V>
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MapVisitor<K, V>(std::marker::PhantomData<(K, V)>);
        impl<'de, K: Deserialize<'de> + Hash + Eq, V: Deserialize<'de> + Clone> Visitor<'de>
            for MapVisitor<K, V>
        {
            type Value = RowMap<K, V>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("native business rows")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
                let mut rows = RowMap::new();
                while let Some((key, value)) = input.next_entry()? {
                    rows.insert(key, value);
                }
                Ok(rows)
            }
        }
        deserializer.deserialize_map(MapVisitor(std::marker::PhantomData))
    }
}

#[cfg(test)]
impl<K: Hash + Eq, V> std::ops::Index<&K> for RowMap<K, V> {
    type Output = V;

    fn index(&self, key: &K) -> &V {
        self.get(key).expect("test row exists")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::native::SharedRow;

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    struct CollisionKey {
        epoch: u64,
        nonce: [u8; 16],
        commitment: [u8; 32],
    }

    impl Hash for CollisionKey {
        fn hash<H: Hasher>(&self, state: &mut H) {
            // Every key collides, including those differing only in the final
            // commitment byte. The complete identity must resolve the bucket.
            state.write_u8(0);
        }
    }

    fn key(value: u8) -> CollisionKey {
        let mut commitment = [0xDA; 32];
        commitment[31] = value;
        CollisionKey {
            epoch: 1,
            nonce: [0xDB; 16],
            commitment,
        }
    }

    #[test]
    fn native_row_map_collisions_replacement_and_relocation_preserve_captured_revisions() {
        let mut rows = RowMap::new();
        for i in 0..64 {
            assert!(rows
                .insert(key(i), SharedRow::new(u64::from(i)).unwrap())
                .is_none());
        }
        let mut captured = None;
        let capture = allocation_counter::measure(|| captured = Some(rows.clone()));
        assert_eq!(
            capture.bytes_total, 0,
            "capture shares the whole index root"
        );
        let captured = captured.unwrap();
        for i in 0..64 {
            let old = &captured[&key(i)];
            let replacement = if i % 2 == 0 {
                old.relocated(u64::from(i) + 100)
            } else {
                SharedRow::new(u64::from(i) + 100).unwrap()
            };
            let removed = rows.insert(key(i), replacement.clone()).unwrap();
            assert!(removed.ptr_eq(old));
            assert_eq!(*removed, u64::from(i));
            assert!(rows[&key(i)].ptr_eq(&replacement));
            assert_eq!(*rows[&key(i)], u64::from(i) + 100);
            assert_eq!(rows[&key(i)].ptr_eq(old), i % 2 == 0);
            assert_eq!(**old, u64::from(i), "captured payload remains immutable");
        }
        for i in 0..64 {
            assert_eq!(*rows.remove(&key(i)).unwrap(), u64::from(i) + 100);
            assert!(!rows.contains_key(&key(i)));
            assert!(rows.remove(&key(i)).is_none());
            assert_eq!(*captured[&key(i)], u64::from(i));
        }
        assert!(rows.is_empty());
        assert_eq!(captured.len(), 64);
    }

    #[test]
    fn native_row_map_map_codec_preserves_complete_keys_and_values_both_directions() {
        let mut rows = RowMap::new();
        for i in 0..64 {
            rows.insert(key(i), SharedRow::new(u64::from(i)).unwrap());
        }
        let encoded = postcard::to_allocvec(&rows).unwrap();
        let original: imbl::HashMap<CollisionKey, SharedRow<u64>> =
            postcard::from_bytes(&encoded).unwrap();
        let encoded = postcard::to_allocvec(&original).unwrap();
        let restored: RowMap<CollisionKey, SharedRow<u64>> =
            postcard::from_bytes(&encoded).unwrap();
        assert_eq!(original.len(), rows.len());
        assert_eq!(restored.len(), rows.len());
        for (key, row) in &rows {
            assert_eq!(**row, *original[key]);
            assert_eq!(**row, *restored[key]);
            assert!(
                !row.ptr_eq(&restored[key]),
                "decoding creates a fresh revision"
            );
        }
    }
}
