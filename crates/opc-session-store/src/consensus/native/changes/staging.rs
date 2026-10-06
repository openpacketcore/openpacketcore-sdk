//! Test-only observation of the actual staging buffer's destruction. The
//! production alias is Vec; this wrapper follows that same Vec through its
//! consuming iterator and drops the marker only AFTER the buffer is freed.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;

pub(super) struct Rows<T> {
    rows: Vec<T>,
    pub(super) allocation_lifetime: Option<Arc<()>>,
}

impl<T> Default for Rows<T> {
    fn default() -> Self {
        Vec::new().into()
    }
}

impl<T> From<Vec<T>> for Rows<T> {
    fn from(rows: Vec<T>) -> Self {
        Self {
            rows,
            allocation_lifetime: None,
        }
    }
}

impl<T> Deref for Rows<T> {
    type Target = Vec<T>;
    fn deref(&self) -> &Self::Target {
        &self.rows
    }
}

impl<T> DerefMut for Rows<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.rows
    }
}

pub(super) struct IntoIter<T> {
    rows: std::vec::IntoIter<T>,
    _allocation_lifetime: Option<Arc<()>>,
}

impl<T> Iterator for IntoIter<T> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        self.rows.next()
    }
}

impl<T> IntoIterator for Rows<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            rows: self.rows.into_iter(),
            _allocation_lifetime: self.allocation_lifetime,
        }
    }
}

impl<'a, T> IntoIterator for &'a Rows<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.rows.iter()
    }
}
