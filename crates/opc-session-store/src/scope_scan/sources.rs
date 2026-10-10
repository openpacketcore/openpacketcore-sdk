//! Namespace-bounded raw readers borrowed only while a retained cut is in use.

use super::engine::{
    kind_name, maximum_record_bytes, native_candidate, InventoryBudget, InventoryCandidate,
    InventoryError, InventorySource,
};
use super::headers::RawScopeRecord;
use super::integrity::ItemKind;
use super::position::{InventoryPosition, LocatorKind};
use crate::scope_authority::ScopeNamespace;
use crate::{scope_storage, SessionKey, SessionKeyType, StableId};
use bytes::Bytes;
use rusqlite::{params, OptionalExtension};
use std::io;

pub(crate) const MALFORMED_QUERY:&str="SELECT rowid FROM session_records INDEXED BY scope_scan_bad_keys
             WHERE tenant=?1 AND nf_kind=?2 AND key_type=?3
             AND key_type IN ('opc-scope-child','opc-scope-claim')
             AND (typeof(stable_id)!='blob' OR length(stable_id)!=64)
             AND CASE WHEN typeof(stable_id)='blob' AND length(stable_id)>=32 THEN substr(stable_id,1,32) ELSE x'' END=?4
             AND rowid>=?5 ORDER BY rowid LIMIT 1";

struct Bounds {
    lower: SessionKey,
    upper: Option<SessionKey>,
    strict: bool,
    prefix: [u8; 32],
}
fn key(
    namespace: &ScopeNamespace,
    kind: ItemKind,
    bytes: &[u8],
) -> Result<SessionKey, InventoryError> {
    Ok(SessionKey {
        tenant: namespace.scope().tenant().clone(),
        nf_kind: namespace.scope().nf_kind().clone(),
        key_type: SessionKeyType::other(kind_name(kind))
            .map_err(|_| InventoryError::InvalidPosition)?,
        stable_id: StableId::new(Bytes::copy_from_slice(bytes))
            .map_err(|_| InventoryError::InvalidPosition)?,
    })
}
fn bounds(
    namespace: &ScopeNamespace,
    kind: ItemKind,
    after: Option<&[u8]>,
) -> Result<Bounds, InventoryError> {
    let prefix =
        scope_storage::namespace_prefix(namespace).map_err(|_| InventoryError::InvalidPosition)?;
    if after.is_some_and(|after| !(32..=64).contains(&after.len()) || !after.starts_with(&prefix)) {
        return Err(InventoryError::InvalidPosition);
    }
    let lower = key(namespace, kind, after.unwrap_or(&prefix))?;
    let mut upper = prefix.to_vec();
    let upper = if let Some(last) = upper.iter().rposition(|byte| *byte != u8::MAX) {
        upper[last] += 1;
        upper.truncate(last + 1);
        Some(key(namespace, kind, &upper)?)
    } else {
        None
    };
    Ok(Bounds {
        lower,
        upper,
        strict: after.is_some(),
        prefix,
    })
}
fn tag(kind: ItemKind) -> u8 {
    match kind {
        ItemKind::Child => 0,
        ItemKind::Claim => 1,
    }
}
fn validate_after(
    namespace: &ScopeNamespace,
    kind: ItemKind,
    after: Option<&InventoryPosition>,
) -> Result<(), InventoryError> {
    if after
        .is_some_and(|position| position.kind != tag(kind) || !position.valid_namespace(namespace))
    {
        return Err(InventoryError::InvalidPosition);
    }
    Ok(())
}

pub(crate) struct SqliteSource<'a> {
    pub(crate) connection: &'a rusqlite::Connection,
    pub(crate) check: &'a dyn Fn() -> io::Result<()>,
    pub(crate) work_exhausted: &'a dyn Fn() -> bool,
}
impl SqliteSource<'_> {
    fn current(&self) -> Result<(), InventoryError> {
        (self.check)().map_err(|_| InventoryError::Interrupted)?;
        if (self.work_exhausted)() {
            return Err(InventoryError::WorkBudget);
        }
        Ok(())
    }
    fn query_error(&self) -> InventoryError {
        self.current().err().unwrap_or(InventoryError::Interrupted)
    }
    fn canonical(
        &self,
        namespace: &ScopeNamespace,
        kind: ItemKind,
        after: Option<&[u8]>,
        budget: &mut InventoryBudget,
    ) -> Result<Option<InventoryCandidate>, InventoryError> {
        self.current()?;
        budget.charge(512)?;
        let bounds = bounds(namespace, kind, after)?;
        // A disjoint partial index prevents malformed rows from consuming the
        // page VM budget before a healthy row can be reached. Both range ends
        // remain direct constraints, including on a late page.
        let sql = if bounds.upper.is_some() {
            "SELECT stable_id FROM session_records INDEXED BY scope_scan_keys
             WHERE tenant=?1 AND nf_kind=?2 AND key_type=?3
             AND key_type IN ('opc-scope-child','opc-scope-claim')
             AND typeof(stable_id)='blob' AND length(stable_id)=64
             AND stable_id>=?4 AND stable_id<?5 AND (?6=0 OR stable_id>?4)
             ORDER BY stable_id LIMIT 1"
        } else {
            "SELECT stable_id FROM session_records INDEXED BY scope_scan_keys
             WHERE tenant=?1 AND nf_kind=?2 AND key_type=?3
             AND key_type IN ('opc-scope-child','opc-scope-claim')
             AND typeof(stable_id)='blob' AND length(stable_id)=64
             AND stable_id>=?4 AND ?5 IS NULL AND (?6=0 OR stable_id>?4)
             ORDER BY stable_id LIMIT 1"
        };
        let mut statement = self
            .connection
            .prepare(sql)
            .map_err(|_| self.query_error())?;
        let mut rows = statement
            .query(params![
                bounds.lower.tenant.as_str(),
                bounds.lower.nf_kind.as_str(),
                bounds.lower.key_type.as_str(),
                bounds.lower.stable_id.as_ref(),
                bounds.upper.as_ref().map(|key| key.stable_id.as_ref()),
                i32::from(bounds.strict)
            ])
            .map_err(|_| self.query_error())?;
        let next = match rows.next().map_err(|_| self.query_error())? {
            None => None,
            Some(row) => {
                let rusqlite::types::ValueRef::Blob(bytes) =
                    row.get_ref(0).map_err(|_| self.query_error())?
                else {
                    return Err(InventoryError::Interrupted);
                };
                if bytes.len() != 64 || !bytes.starts_with(&bounds.prefix) {
                    return Err(InventoryError::Interrupted);
                }
                let mut key = bounds.lower;
                key.stable_id = StableId::new(Bytes::copy_from_slice(bytes))
                    .map_err(|_| InventoryError::Interrupted)?;
                Some(native_candidate(namespace, key)?)
            }
        };
        self.current()?;
        Ok(next)
    }
    fn malformed(
        &self,
        namespace: &ScopeNamespace,
        kind: ItemKind,
        known: bool,
        after: Option<i64>,
        budget: &mut InventoryBudget,
    ) -> Result<Option<InventoryCandidate>, InventoryError> {
        self.current()?;
        budget.charge(512)?;
        let prefix = scope_storage::namespace_prefix(namespace)
            .map_err(|_| InventoryError::InvalidPosition)?;
        // The index expression owns at most the 32-byte prefix. The returned
        // scalar is the exact transaction-stable rowid, never a key prefix
        // used as a substitute identity and never the malformed raw key.
        let Some(lower) = after.map_or(Some(i64::MIN), |rowid| rowid.checked_add(1)) else {
            return Ok(None);
        };
        let rowid: Option<i64> = self
            .connection
            .query_row(
                MALFORMED_QUERY,
                params![
                    namespace.scope().tenant().as_str(),
                    namespace.scope().nf_kind().as_str(),
                    kind_name(kind),
                    if known { prefix.as_slice() } else { &[] },
                    lower
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| self.query_error())?;
        self.current()?;
        Ok(rowid.map(|rowid| InventoryCandidate {
            position: InventoryPosition::sqlite(tag(kind), known, rowid),
            key: None,
        }))
    }
}
impl InventorySource for SqliteSource<'_> {
    fn next_candidate(
        &mut self,
        namespace: &ScopeNamespace,
        kind: ItemKind,
        after: Option<&InventoryPosition>,
        budget: &mut InventoryBudget,
    ) -> Result<Option<InventoryCandidate>, InventoryError> {
        validate_after(namespace, kind, after)?;
        if after.is_some_and(|after| {
            matches!(
                after.locator,
                LocatorKind::NativeKnown | LocatorKind::NativeUnknown
            )
        }) {
            return Err(InventoryError::InvalidPosition);
        }
        for phase in [
            LocatorKind::Canonical,
            LocatorKind::SqliteKnown,
            LocatorKind::SqliteUnknown,
        ] {
            if after.is_some_and(|after| after.locator > phase) {
                continue;
            }
            let after = after.filter(|after| after.locator == phase);
            let next = if phase == LocatorKind::Canonical {
                self.canonical(
                    namespace,
                    kind,
                    after.map(|after| after.bytes.as_slice()),
                    budget,
                )?
            } else {
                self.malformed(
                    namespace,
                    kind,
                    phase == LocatorKind::SqliteKnown,
                    after.and_then(InventoryPosition::rowid),
                    budget,
                )?
            };
            if next.is_some() {
                return Ok(next);
            }
        }
        Ok(None)
    }
    fn read(
        &mut self,
        key: &SessionKey,
        budget: &mut InventoryBudget,
    ) -> Result<RawScopeRecord, InventoryError> {
        self.current()?;
        budget.charge(512)?;
        let size:Option<Option<i64>>=self.connection.query_row(
            "SELECT CASE WHEN typeof(payload)='blob' THEN octet_length(payload) END FROM session_records WHERE tenant=?1 AND nf_kind=?2 AND key_type=?3 AND stable_id=?4",
            params![key.tenant.as_str(),key.nf_kind.as_str(),key.key_type.as_str(),key.stable_id.as_ref()],|row|row.get(0)).optional().map_err(|_|self.query_error())?;
        let Some(Some(size)) = size else {
            return Ok(if size.is_none() {
                RawScopeRecord::Missing
            } else {
                RawScopeRecord::Corrupt
            });
        };
        let size = usize::try_from(size).map_err(|_| InventoryError::Interrupted)?;
        if size > maximum_record_bytes(key) {
            return Ok(RawScopeRecord::Corrupt);
        }
        budget.charge(size)?;
        let record = crate::sqlite::scope_scan::read_raw_record(
            self.connection,
            key,
            maximum_record_bytes(key),
        )
        .map_err(|_| self.query_error())?;
        self.current()?;
        Ok(record)
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct NativeSource<'a> {
    pub(crate) capture: &'a crate::consensus::native::ScopeRecordCapture,
    pub(crate) check: &'a dyn Fn() -> io::Result<()>,
    pub(crate) work_exhausted: &'a dyn Fn() -> bool,
}
#[cfg(target_os = "linux")]
impl NativeSource<'_> {
    fn current(&self) -> Result<(), InventoryError> {
        (self.check)().map_err(|_| InventoryError::Interrupted)?;
        if (self.work_exhausted)() {
            return Err(InventoryError::WorkBudget);
        }
        Ok(())
    }
}
#[cfg(target_os = "linux")]
impl InventorySource for NativeSource<'_> {
    fn next_candidate(
        &mut self,
        namespace: &ScopeNamespace,
        kind: ItemKind,
        after: Option<&InventoryPosition>,
        budget: &mut InventoryBudget,
    ) -> Result<Option<InventoryCandidate>, InventoryError> {
        use std::ops::Bound::{Excluded, Included, Unbounded};
        validate_after(namespace, kind, after)?;
        if after.is_some_and(|after| {
            matches!(
                after.locator,
                LocatorKind::SqliteKnown | LocatorKind::SqliteUnknown
            )
        }) {
            return Err(InventoryError::InvalidPosition);
        }
        for (index, phase) in [
            LocatorKind::Canonical,
            LocatorKind::NativeKnown,
            LocatorKind::NativeUnknown,
        ]
        .into_iter()
        .enumerate()
        {
            if after.is_some_and(|after| after.locator > phase) {
                continue;
            }
            self.current()?;
            budget.charge(512)?;
            let after = after.filter(|after| after.locator == phase);
            let bounds = if phase == LocatorKind::NativeUnknown {
                Bounds {
                    lower: key(
                        namespace,
                        kind,
                        after.map_or(&[0], |after| after.bytes.as_slice()),
                    )?,
                    upper: None,
                    strict: after.is_some(),
                    prefix: [0; 32],
                }
            } else {
                bounds(namespace, kind, after.map(|after| after.bytes.as_slice()))?
            };
            let lower = if bounds.strict {
                Excluded(&bounds.lower)
            } else {
                Included(&bounds.lower)
            };
            let upper = bounds.upper.as_ref().map_or(Unbounded, Excluded);
            let next = self
                .capture
                .records()
                .scan_range(index, lower, upper)
                .next()
                .map(|(key, _)| key)
                .filter(|key| {
                    key.tenant == bounds.lower.tenant
                        && key.nf_kind == bounds.lower.nf_kind
                        && key.key_type == bounds.lower.key_type
                        && (phase == LocatorKind::NativeUnknown
                            || key.stable_id.as_ref().starts_with(&bounds.prefix))
                })
                .cloned();
            self.current()?;
            if let Some(key) = next {
                if phase == LocatorKind::NativeUnknown {
                    return Ok(Some(InventoryCandidate {
                        position: InventoryPosition {
                            kind: tag(kind),
                            locator: phase,
                            bytes: key.stable_id.as_ref().to_vec(),
                        },
                        key: None,
                    }));
                }
                return native_candidate(namespace, key).map(Some);
            }
        }
        Ok(None)
    }
    fn read(
        &mut self,
        key: &SessionKey,
        budget: &mut InventoryBudget,
    ) -> Result<RawScopeRecord, InventoryError> {
        self.current()?;
        budget.charge(512)?;
        let row = self.capture.records().get(key);
        if let Some(row) = row {
            if row.payload.len() > maximum_record_bytes(key) {
                return Ok(RawScopeRecord::Corrupt);
            }
            budget.charge(row.payload.len())?;
        }
        let record = RawScopeRecord::from_native(row, maximum_record_bytes(key));
        self.current()?;
        Ok(record)
    }
}
