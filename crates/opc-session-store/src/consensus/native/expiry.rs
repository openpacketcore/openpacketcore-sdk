//! Derived resident business indexes. Full admission rebuilds these from every
//! admitted key; publication updates only changed keys. Snapshot captures share
//! immutable tree roots. Their resident nodes count toward the existing process
//! RSS limit; they contain no file-verification certificate or decoded payload.

use super::*;
use std::cmp::Ordering;

#[derive(Clone, PartialEq, Eq)]
struct OrderedKey(SessionKey);

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
    records: im::OrdSet<(Timestamp, OrderedKey)>,
    ordered_records: im::OrdSet<OrderedKey>,
    leases: im::OrdSet<(Timestamp, OrderedKey)>,
    released: im::OrdSet<OrderedKey>,
    v1_due: im::OrdSet<(Timestamp, [u8; 16])>,
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
        let key = OrderedKey(key.clone());
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
            .map(|key| Excluded(OrderedKey(key.clone())))
            .unwrap_or(Unbounded);
        self.ordered_records
            .range((start, Unbounded))
            .map(|key| &key.0)
    }

    pub(super) fn due_record(&self, now: Timestamp) -> Option<SessionKey> {
        self.records
            .get_min()
            .filter(|(until, _)| *until <= now)
            .map(|(_, key)| key.0.clone())
    }

    pub(super) fn due_lease(&self, now: Timestamp) -> Option<SessionKey> {
        self.released
            .get_min()
            .map(|key| key.0.clone())
            .or_else(|| {
                self.leases
                    .get_min()
                    .filter(|(until, _)| *until <= now)
                    .map(|(_, key)| key.0.clone())
            })
    }
}
