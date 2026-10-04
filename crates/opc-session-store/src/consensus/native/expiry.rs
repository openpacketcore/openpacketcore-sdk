//! Derived resident business indexes. Full admission rebuilds these from every
//! admitted key; publication updates only changed keys. Snapshot captures share
//! immutable tree roots. Their resident nodes count toward the existing process
//! RSS limit; they contain no file-verification certificate or decoded payload.

use super::*;
use std::cmp::Ordering;
use std::sync::Arc;

// The same immutable complete key belongs to several derived indexes and
// their branch separators. Share its owner instead of duplicating strings
// and reserving the full key width in every tree slot. Ordering and equality
// still compare the original values, never the allocation address.
#[derive(Clone, PartialEq, Eq)]
struct OrderedKey(Arc<SessionKey>);

impl Ord for OrderedKey {
    fn cmp(&self, other: &Self) -> Ordering {
        fn kind(value: &crate::SessionKeyType) -> u8 {
            match value {
                crate::SessionKeyType::SubscriberContext => 0,
                crate::SessionKeyType::PduSession => 1,
                crate::SessionKeyType::TeidMapping => 2,
                crate::SessionKeyType::PfcpSeid => 3,
                crate::SessionKeyType::HandoverTransaction => 4,
                crate::SessionKeyType::Other(_) => 5,
            }
        }
        let left = &self.0;
        let right = &other.0;
        (
            left.tenant.as_str(),
            left.nf_kind.as_str(),
            left.key_type.as_str(),
            kind(&left.key_type),
            left.stable_id.as_bytes(),
        )
            .cmp(&(
                right.tenant.as_str(),
                right.nf_kind.as_str(),
                right.key_type.as_str(),
                kind(&right.key_type),
                right.stable_id.as_bytes(),
            ))
    }
}

impl PartialOrd for OrderedKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Default)]
pub(super) struct ExpiryIndex {
    records: imbl::OrdSet<(Timestamp, OrderedKey)>,
    ordered_records: imbl::OrdSet<OrderedKey>,
    leases: imbl::OrdSet<(Timestamp, OrderedKey)>,
    released: imbl::OrdSet<OrderedKey>,
    v1_due: imbl::OrdSet<(Timestamp, [u8; 16])>,
    v1_count: usize,
}

impl ExpiryIndex {
    pub(super) fn replace_request(
        &mut self,
        id: SessionConsensusRequestId,
        before: Option<&NativeGenericReceipt>,
        after: Option<&NativeGenericReceipt>,
    ) -> io::Result<()> {
        if let Some(NativeGenericReceipt::FencedV1(row)) = before {
            self.v1_count = self
                .v1_count
                .checked_sub(1)
                .ok_or_else(|| invalid("native V1 index count underflow"))?;
            if row.response.is_some() {
                self.v1_due.remove(&(row.retained_until, *id.as_bytes()));
            }
        }
        if let Some(NativeGenericReceipt::FencedV1(row)) = after {
            self.v1_count = self
                .v1_count
                .checked_add(1)
                .ok_or_else(|| invalid("native V1 index count overflow"))?;
            if row.response.is_some() {
                self.v1_due.insert((row.retained_until, *id.as_bytes()));
            }
        }
        Ok(())
    }

    pub(super) fn v1_count(&self) -> usize {
        self.v1_count
    }

    pub(super) fn validate_requests(&self, frontiers: &NativeFrontiers) -> io::Result<()> {
        if self.v1_count > crate::fenced_transition::FENCED_TRANSITION_MAX_HISTORY_ENTRIES
            || (self.v1_count != 0 && frontiers.v1_activation.is_none())
        {
            return Err(invalid("native V1 index count or activation differs"));
        }
        Ok(())
    }

    pub(super) fn due_v1(&self, now: Timestamp) -> Option<SessionConsensusRequestId> {
        self.v1_due
            .get_min()
            .filter(|(until, _)| *until <= now)
            .map(|(_, id)| SessionConsensusRequestId::from_bytes(*id))
    }

    pub(super) fn replace(
        &mut self,
        key: &SessionKey,
        before: Option<&NativeKeyState>,
        after: Option<&NativeKeyState>,
    ) {
        let key = OrderedKey(Arc::new(key.clone()));
        if let Some(before) = before {
            if before.record.is_some() {
                self.ordered_records.remove(&key);
            }
            if let Some(until) = before.record.as_ref().and_then(|row| row.expires_at) {
                self.records.remove(&(until, key.clone()));
            }
            if let Some(lease) = &before.lease {
                if lease.active {
                    self.leases.remove(&(lease.guard_expires_at, key.clone()));
                } else {
                    self.released.remove(&key);
                }
            }
        }
        if let Some(after) = after {
            if after.record.is_some() {
                self.ordered_records.insert(key.clone());
            }
            if let Some(until) = after.record.as_ref().and_then(|row| row.expires_at) {
                self.records.insert((until, key.clone()));
            }
            if let Some(lease) = &after.lease {
                if lease.active {
                    self.leases.insert((lease.guard_expires_at, key));
                } else {
                    self.released.insert(key);
                }
            }
        }
    }

    pub(super) fn ordered_records(
        &self,
        after: Option<&SessionKey>,
    ) -> impl Iterator<Item = &SessionKey> {
        use std::ops::Bound::{Excluded, Unbounded};
        let start = after
            .map(|key| Excluded(OrderedKey(Arc::new(key.clone()))))
            .unwrap_or(Unbounded);
        self.ordered_records
            .range((start, Unbounded))
            .map(|key| key.0.as_ref())
    }

    pub(super) fn due_record(&self, now: Timestamp) -> Option<SessionKey> {
        self.records
            .get_min()
            .filter(|(until, _)| *until <= now)
            .map(|(_, key)| (*key.0).clone())
    }

    pub(super) fn due_lease(&self, now: Timestamp) -> Option<SessionKey> {
        self.released
            .get_min()
            .map(|key| (*key.0).clone())
            .or_else(|| {
                self.leases
                    .get_min()
                    .filter(|(until, _)| *until <= now)
                    .map(|(_, key)| (*key.0).clone())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use allocation_counter::measure;
    use changes::tests::{fixture, time};
    use opc_types::{NetworkFunctionKind, TenantId};

    fn key(number: u64) -> SessionKey {
        SessionKey {
            tenant: TenantId::from_static("native-expiry-owner"),
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: crate::SessionKeyType::PduSession,
            stable_id: bytes::Bytes::copy_from_slice(&number.to_be_bytes())
                .try_into()
                .unwrap(),
        }
    }

    #[test]
    fn native_expiry_index_owns_bounded_full_keys_and_preserves_captured_order() {
        const ROWS: u64 = 4096;
        let (storage, _, _) = fixture();
        let mut row = (**storage.business.keys.values().next().unwrap()).clone();
        row.record.as_mut().unwrap().expires_at = Some(time(20));
        row.lease.as_mut().unwrap().guard_expires_at = time(30);
        // These are the production derived indexes, with a distinct complete
        // key in all three trees. The input row's payload is never indexed.
        // No fixture key retains the newly allocated identifier backing.
        let mut index = ExpiryIndex::default();
        let owned = measure(|| {
            for number in (0..ROWS).rev() {
                index.replace(&key(number), None, Some(&row));
            }
        });
        eprintln!(
            "native_expiry_index_owner rows={ROWS} live={} allocations={} peak={}",
            owned.bytes_current, owned.count_current, owned.bytes_max,
        );
        assert_eq!(index.ordered_records(None).count(), ROWS as usize);
        for (number, actual) in index.ordered_records(None).enumerate() {
            assert_eq!(*actual, key(number as u64));
        }
        assert_eq!(index.due_record(time(19)), None);
        assert_eq!(index.due_record(time(20)), Some(key(0)));
        assert_eq!(index.due_lease(time(29)), None);
        assert_eq!(index.due_lease(time(30)), Some(key(0)));
        let mut captured = None;
        let capture = measure(|| captured = Some(index.clone()));
        assert_eq!(capture.count_total, 0, "capture shares immutable roots");
        let captured = captured.unwrap();
        let mut released = row.clone();
        released.record = None;
        released.lease.as_mut().unwrap().active = false;
        for number in 0..ROWS {
            let key = key(number);
            assert_eq!(index.due_record(time(20)), Some(key.clone()));
            // An independently reconstructed key must find the old value;
            // pointer identity cannot replace complete key comparison.
            index.replace(&key, Some(&row), Some(&released));
            assert_eq!(index.due_lease(time(1)), Some(key.clone()));
            index.replace(&key, Some(&released), None);
            assert_eq!(captured.due_record(time(20)), Some(self::key(0)));
            assert_eq!(captured.due_lease(time(30)), Some(self::key(0)));
            assert_eq!(
                captured.ordered_records(Some(&key)).next(),
                (number + 1 < ROWS).then(|| self::key(number + 1)).as_ref(),
            );
        }
        assert_eq!(index.ordered_records(None).next(), None);
        assert_eq!(index.due_record(time(59)), None);
        assert_eq!(index.due_lease(time(59)), None);
        drop(index);
        let released = measure(|| drop(captured));
        assert_eq!(owned.bytes_current, -released.bytes_current);
        assert_eq!(owned.count_current, -released.count_current);
        // This owner is additional to the authoritative key map, receipts,
        // logs and runtime. Bound actual retained allocations, not type sizes.
        // The original three-voter 2 GiB RSS qualification remains separate.
        assert!(
            owned.bytes_current <= ROWS as i64 * 384,
            "expiry indexes retain {} bytes for {ROWS} complete keys",
            owned.bytes_current,
        );
    }

    #[test]
    fn native_expiry_order_distinguishes_complete_namespace_and_key_bytes() {
        let (storage, _, _) = fixture();
        let row = &**storage.business.keys.values().next().unwrap();
        let base = key(7);
        let mut tenant = base.clone();
        tenant.tenant = TenantId::from_static("native-expiry-other-tenant");
        let mut nf = base.clone();
        nf.nf_kind = NetworkFunctionKind::from_static("upf");
        let mut kind = base.clone();
        kind.key_type = crate::SessionKeyType::TeidMapping;
        let keys = [base, tenant, nf, kind, key(8)];
        let mut index = ExpiryIndex::default();
        for key in &keys {
            index.replace(key, None, Some(row));
        }
        assert_eq!(index.ordered_records(None).count(), keys.len());
        for key in &keys {
            assert!(index.ordered_records(None).any(|actual| actual == key));
        }
        for (removed, key) in keys.iter().enumerate() {
            index.replace(&key.clone(), Some(row), None);
            assert_eq!(
                index.ordered_records(None).count(),
                keys.len() - removed - 1
            );
            for retained in &keys[removed + 1..] {
                assert!(index.ordered_records(None).any(|actual| actual == retained));
            }
        }
    }
}
