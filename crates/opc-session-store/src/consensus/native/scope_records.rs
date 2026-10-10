//! A narrow immutable inventory of reserved scope records at one admitted cut.
//!
//! Publication replaces only touched rows. A capture shares this root, without
//! retaining the business proof, ordinary records, receipts, logs or snapshots.
//! This index preserves raw records, including malformed bodies and key/body
//! mismatches; decoding and final per-item inspection belong to the scan engine.

use super::*;
use expiry::OrderedKey;
use std::alloc::Layout;
use std::ops::Bound;
use std::sync::atomic::AtomicUsize;

// imbl 7.0.2 uses a B+ tree with at most 16 keys per node. Here keys and values
// are single Arc handles. A leaf needs 16 pairs plus its chunk bounds and Arc
// header; a branch needs 16 key handles, 17 child handles, chunk bounds, a tag,
// level and Arc header. Both fit 512 bytes on our supported pointer widths.
// Every nonempty leaf owns at least one entry, and every branch has at least
// two children, so n entries reach at most 2*n+1 nodes, including an empty root.
// This diagnostic describes shared storage reachability, not per-view memory.
// A branch separator shares its key's Arc owner, already counted with the row.
#[cfg(test)]
const TREE_NODE_BYTES: usize = 512;

// The root handle and bounded identity, membership (at most five members),
// applied position, configuration fingerprint and retention bookkeeping fit
// within this context reservation. A view reserves two bounded pages for its
// retained reply and concurrent classification work. The shared immutable
// storage index is not a per-view allocation or an admission ceiling.
const CAPTURE_CONTEXT_BYTES: usize = 64 * 1024;
const CAPTURE_RESERVATION_BYTES: usize =
    CAPTURE_CONTEXT_BYTES + 2 * crate::RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES;

#[derive(Debug, thiserror::Error)]
enum ScopeCaptureError {
    #[cfg(test)]
    #[error("native scope capture reservation overflow")]
    ReservationOverflow,
    #[error("native scope capture configuration changed")]
    ConfigurationChanged,
}

struct ScopeRecordCell {
    record: StoredSessionRecord,
    allocation_bytes: Option<usize>,
}

#[derive(Clone)]
pub(crate) struct ScopeRecordIndex {
    records: imbl::OrdMap<OrderedKey, Arc<ScopeRecordCell>>,
    // Canonical, malformed attributable, and malformed unattributable keys.
    // Disjoint subindexes share normalized key and record owners with `records`.
    scans: [imbl::OrdMap<OrderedKey, Arc<ScopeRecordCell>>; 3],
    // Reachability diagnostics saturate to unknown rather than wrapping. This
    // shared-storage measurement does not control per-view admission.
    record_bytes: Option<usize>,
}

impl Default for ScopeRecordIndex {
    fn default() -> Self {
        Self {
            records: imbl::OrdMap::new(),
            scans: std::array::from_fn(|_| imbl::OrdMap::new()),
            record_bytes: Some(0),
        }
    }
}

impl ScopeRecordIndex {
    pub(super) fn replace(&mut self, key: &SessionKey, row: Option<&StoredSessionRecord>) {
        // Public StableId values can be slices of arbitrarily large owners.
        // Both physical-key and body-key owners must be independent before the
        // immutable capture may retain them. The payload Arc is shared and its
        // actual backing capacity is charged instead of being copied here.
        let mut key = key.clone();
        key.normalize_log_row_reuse_backing();
        let phase = match key.key_type.as_str() {
            "opc-scope-child" | "opc-scope-claim" => {
                if row.is_some_and(|row| {
                    crate::scope_storage::scope_scan_prefix_mismatch(
                        key.stable_id.as_ref(),
                        row.payload.as_bytes(),
                    )
                }) {
                    Some(2)
                } else {
                    match key.stable_id.as_ref().len() {
                        64 => Some(0),
                        32..64 => Some(1),
                        1..32 => Some(2),
                        _ => None,
                    }
                }
            }
            _ => None,
        };
        let key = OrderedKey(Arc::new(key));
        // Replacing a body can change attribution without changing the key.
        // Remove its previous category before publishing the new one.
        for scan in &mut self.scans {
            scan.remove(&key);
        }
        if let Some(previous) = self.records.remove(&key) {
            self.record_bytes = self
                .record_bytes
                .and_then(|bytes| bytes.checked_sub(previous.allocation_bytes?));
        }
        if let Some(row) = row {
            let mut record = row.clone();
            record.key.normalize_log_row_reuse_backing();
            let allocation_bytes = retained_record_bytes(key.0.as_ref(), &record);
            self.record_bytes = self
                .record_bytes
                .and_then(|bytes| bytes.checked_add(allocation_bytes?));
            let cell = Arc::new(ScopeRecordCell {
                record,
                allocation_bytes,
            });
            if let Some(phase) = phase {
                self.scans[phase].insert(key.clone(), cell.clone());
            }
            self.records.insert(key, cell);
        }
    }

    pub(crate) fn get(&self, key: &SessionKey) -> Option<&StoredSessionRecord> {
        self.records
            .get(&OrderedKey(Arc::new(key.clone())))
            .map(|cell| &cell.record)
    }

    #[cfg(test)]
    pub(crate) fn range(
        &self,
        lower: Bound<&SessionKey>,
        upper: Bound<&SessionKey>,
    ) -> impl Iterator<Item = (&SessionKey, &StoredSessionRecord)> {
        let lower = lower.map(|key| OrderedKey(Arc::new(key.clone())));
        let upper = upper.map(|key| OrderedKey(Arc::new(key.clone())));
        self.records
            .range((lower, upper))
            .map(|(key, cell)| (key.0.as_ref(), &cell.record))
    }

    pub(crate) fn scan_range(
        &self,
        phase: usize,
        lower: Bound<&SessionKey>,
        upper: Bound<&SessionKey>,
    ) -> impl Iterator<Item = (&SessionKey, &StoredSessionRecord)> {
        let lower = lower.map(|key| OrderedKey(Arc::new(key.clone())));
        let upper = upper.map(|key| OrderedKey(Arc::new(key.clone())));
        self.scans[phase]
            .range((lower, upper))
            .map(|(key, cell)| (key.0.as_ref(), &cell.record))
    }

    #[cfg(test)]
    pub(crate) fn retained_bytes(&self) -> io::Result<usize> {
        // The primary tree reaches at most 2*n+1 nodes. The disjoint scan
        // trees have at most n total entries and reach at most 2*n+3 nodes.
        let bytes = self
            .records
            .len()
            .checked_mul(4)
            .and_then(|nodes| nodes.checked_add(4))
            .and_then(|nodes| nodes.checked_mul(TREE_NODE_BYTES))
            .and_then(|nodes| nodes.checked_add(self.record_bytes?))
            .and_then(|bytes| bytes.checked_add(CAPTURE_CONTEXT_BYTES));
        bytes.ok_or_else(|| io::Error::other(ScopeCaptureError::ReservationOverflow))
    }
}

fn arc_allocation_bytes<T>() -> Option<usize> {
    let (layout, _) = Layout::new::<[AtomicUsize; 2]>()
        .extend(Layout::new::<T>())
        .ok()?;
    Some(layout.pad_to_align().size())
}

fn retained_record_bytes(key: &SessionKey, record: &StoredSessionRecord) -> Option<usize> {
    arc_allocation_bytes::<SessionKey>()?
        .checked_add(key.log_row_reuse_allocation_bytes()?)?
        .checked_add(arc_allocation_bytes::<ScopeRecordCell>()?)?
        .checked_add(record.key.log_row_reuse_allocation_bytes()?)?
        .checked_add(record.owner.allocation_capacity())?
        .checked_add(record.state_type.allocation_capacity())?
        .checked_add(record.payload.log_row_reuse_allocation_bytes()?)
}

pub(crate) struct ScopeRecordCapture {
    records: ScopeRecordIndex,
    identity: SessionConsensusIdentity,
    members: BTreeSet<SessionConsensusNodeId>,
    roster_root: Option<[u8; 32]>,
    applied: Option<LogId<SessionConsensusNodeId>>,
}

impl ScopeRecordCapture {
    pub(crate) fn records(&self) -> &ScopeRecordIndex {
        &self.records
    }

    pub(crate) fn applied(&self) -> Option<LogId<SessionConsensusNodeId>> {
        self.applied
    }

    #[cfg(test)]
    pub(crate) fn retained_bytes(&self) -> io::Result<usize> {
        self.records.retained_bytes()
    }

    pub(crate) fn require_current_authority(&self, current: &NativeStorage) -> io::Result<()> {
        let business = current.log.require_coherent_business(&current.business)?;
        let (identity, members, _) = business.context();
        if self.identity != identity
            || &self.members != members
            || self.roster_root != roster_root(current)
        {
            return Err(io::Error::other(ScopeCaptureError::ConfigurationChanged));
        }
        Ok(())
    }
}

fn roster_root(storage: &NativeStorage) -> Option<[u8; 32]> {
    storage
        .business
        .roster_root
        .as_deref()
        .map(crate::fenced_mutation_roster::RosterAttestationTrustRootV1::fingerprint)
}

impl NativeStorage {
    /// Borrow the live narrow index for bounded header checks. This does not
    /// clone a root, retain a business proof, or synthesize absent headers.
    pub(crate) fn scope_scan_headers(
        &self,
        identity: SessionConsensusIdentity,
        namespace: &crate::scope_authority::ScopeNamespace,
        stamp: &crate::scope_authority::ScopeAuthorityStamp,
    ) -> io::Result<
        Result<crate::scope_scan::headers::CapturedHeaders, crate::scope_scan::ScopeScanError>,
    > {
        let business = self.log.require_coherent_business(&self.business)?;
        if business.context().0 != identity {
            return Err(io::Error::other("scope scan storage identity differs"));
        }
        let records = business.expiry.scope_records();
        Ok(crate::scope_scan::headers::decode_headers(
            namespace,
            stamp,
            |key, maximum| {
                Ok(crate::scope_scan::headers::RawScopeRecord::from_native(
                    records.get(key),
                    maximum,
                ))
            },
        ))
    }

    /// Per-view context and bounded page reservation. Shared storage roots and
    /// their reachable rows are not multiplied into every view's reservation.
    pub(crate) fn scope_record_bytes(&self) -> io::Result<usize> {
        self.log.require_coherent_business(&self.business)?;
        Ok(CAPTURE_RESERVATION_BYTES)
    }

    pub(crate) fn capture_scope_records(&self) -> io::Result<ScopeRecordCapture> {
        // This checks the exact admitted log/business pair without traversing
        // historical rows. Neither certificate is retained by the result.
        let business = self.log.require_coherent_business(&self.business)?;
        let (identity, members, frontiers) = business.context();
        let records = business.expiry.scope_records();
        Ok(ScopeRecordCapture {
            records: records.clone(),
            identity,
            members: members.clone(),
            roster_root: roster_root(self),
            applied: frontiers.applied,
        })
    }
}

#[cfg(test)]
#[path = "scope_records_tests.rs"]
mod tests;
