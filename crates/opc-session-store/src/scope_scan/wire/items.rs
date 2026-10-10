//! Bounded final item observations, using the shared stored-row codec.
use super::*;
use crate::scope_scan::codec::{Reader, Writer};
use crate::scope_scan::engine::{InspectedItem, InventoryPosition};
use crate::scope_scan::integrity::{
    ClaimHolder, FinalItemInspection, IntegrityFault, ItemDisposition, ItemFailure, ItemKind,
};
use crate::scope_scan::position::LocatorKind;
use crate::scope_storage::{self, ScopeRow};

pub(super) struct Memory {
    payload: usize,
    retained: usize,
}
impl Memory {
    pub(super) fn new() -> Self {
        Self {
            payload: 0,
            retained: 4096,
        }
    }
    fn add(&mut self, payload: usize) -> Result<(), ScopeScanWireError> {
        self.payload = self
            .payload
            .checked_add(payload)
            .ok_or(ScopeScanWireError)?;
        self.retained = self
            .retained
            .checked_add(
                payload
                    .checked_mul(2)
                    .and_then(|v| v.checked_add(4096))
                    .ok_or(ScopeScanWireError)?,
            )
            .ok_or(ScopeScanWireError)?;
        if self.payload > MAX_SCOPE_SCAN_REPLY_BYTES
            || self.retained > crate::RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES
        {
            return Err(ScopeScanWireError);
        }
        Ok(())
    }
}
fn kind_tag(kind: ItemKind) -> u8 {
    match kind {
        ItemKind::Child => 0,
        ItemKind::Claim => 1,
    }
}
fn kind(tag: u8) -> Result<ItemKind, ScopeScanWireError> {
    match tag {
        0 => Ok(ItemKind::Child),
        1 => Ok(ItemKind::Claim),
        _ => Err(ScopeScanWireError),
    }
}
fn valid_key(key: &[u8; 32]) -> Result<(), ScopeScanWireError> {
    if key == &[0; 32] {
        Err(ScopeScanWireError)
    } else {
        Ok(())
    }
}
fn write_holder(w: &mut Writer, holder: ClaimHolder) -> Result<(), ScopeScanWireError> {
    valid_key(&holder.child)?;
    if !(1..=i64::MAX as u64).contains(&holder.birth) {
        return Err(ScopeScanWireError);
    }
    w.put(&holder.child)?;
    w.u64(holder.birth)
}
fn read_holder(r: &mut Reader<'_>) -> Result<ClaimHolder, ScopeScanWireError> {
    let holder = ClaimHolder {
        child: r.array()?,
        birth: r.u64()?,
    };
    valid_key(&holder.child)?;
    if !(1..=i64::MAX as u64).contains(&holder.birth) {
        return Err(ScopeScanWireError);
    }
    Ok(holder)
}
fn write_disposition(w: &mut Writer, value: ItemDisposition) -> Result<(), ScopeScanWireError> {
    match value {
        ItemDisposition::LiveChild => w.u8(0),
        ItemDisposition::ChildTombstone => w.u8(1),
        ItemDisposition::UnrestorableChild => w.u8(2),
        ItemDisposition::ClaimHeld(holder) => {
            w.u8(3)?;
            write_holder(w, holder)
        }
        ItemDisposition::ClaimHeldUnknown => w.u8(4),
        ItemDisposition::ClaimReleased => w.u8(5),
        ItemDisposition::MissingAtCut => w.u8(6),
    }
}
fn read_disposition(r: &mut Reader<'_>) -> Result<ItemDisposition, ScopeScanWireError> {
    Ok(match r.u8()? {
        0 => ItemDisposition::LiveChild,
        1 => ItemDisposition::ChildTombstone,
        2 => ItemDisposition::UnrestorableChild,
        3 => ItemDisposition::ClaimHeld(read_holder(r)?),
        4 => ItemDisposition::ClaimHeldUnknown,
        5 => ItemDisposition::ClaimReleased,
        6 => ItemDisposition::MissingAtCut,
        _ => return Err(ScopeScanWireError),
    })
}
fn write_failure(w: &mut Writer, failure: ItemFailure) -> Result<(), ScopeScanWireError> {
    match failure {
        ItemFailure::Missing { kind, key } => {
            valid_key(&key)?;
            w.u8(0)?;
            w.u8(kind_tag(kind))?;
            w.put(&key)
        }
        ItemFailure::Corrupt { kind, key, reason } => {
            w.u8(1)?;
            w.u8(kind_tag(kind))?;
            w.u8(u8::from(key.is_some()))?;
            if let Some(key) = key {
                valid_key(&key)?;
                w.put(&key)?;
            }
            w.u8(match reason {
                IntegrityFault::Encoding => 0,
                IntegrityFault::Key => 1,
                IntegrityFault::Header => 2,
                IntegrityFault::Ownership => 3,
            })
        }
    }
}
fn read_failure(r: &mut Reader<'_>) -> Result<ItemFailure, ScopeScanWireError> {
    let tag = r.u8()?;
    let kind = kind(r.u8()?)?;
    match tag {
        0 => {
            let key = r.array()?;
            valid_key(&key)?;
            Ok(ItemFailure::Missing { kind, key })
        }
        1 => {
            let key = if r.boolean()? {
                let key = r.array()?;
                valid_key(&key)?;
                Some(key)
            } else {
                None
            };
            let reason = match r.u8()? {
                0 => IntegrityFault::Encoding,
                1 => IntegrityFault::Key,
                2 => IntegrityFault::Header,
                3 => IntegrityFault::Ownership,
                _ => return Err(ScopeScanWireError),
            };
            Ok(ItemFailure::Corrupt { kind, key, reason })
        }
        _ => Err(ScopeScanWireError),
    }
}
fn valid_position(cut: &ScopeCut, position: &InventoryPosition) -> Result<(), ScopeScanWireError> {
    if !position.valid_namespace(cut.namespace()) {
        return Err(ScopeScanWireError);
    }
    Ok(())
}
fn valid_item(cut: &ScopeCut, item: &InspectedItem) -> Result<(), ScopeScanWireError> {
    valid_position(cut, &item.position)?;
    if item.child.is_some() && item.claim.is_some() {
        return Err(ScopeScanWireError);
    }
    if let Some(child) = &item.child {
        if item.position.kind != 0
            || child.namespace() != cut.namespace()
            || scope_storage::child_key(cut.namespace(), child.key())
                .map_err(|_| ScopeScanWireError)?
                .stable_id
                .as_ref()
                != item.position.bytes
        {
            return Err(ScopeScanWireError);
        }
    }
    if let Some(claim) = &item.claim {
        if item.position.kind != 1
            || &claim.namespace != cut.namespace()
            || scope_storage::claim_key(cut.namespace(), claim.key)
                .map_err(|_| ScopeScanWireError)?
                .stable_id
                .as_ref()
                != item.position.bytes
        {
            return Err(ScopeScanWireError);
        }
    }
    let inspection = &item.inspection;
    if item.position.locator != LocatorKind::Canonical {
        let expected = crate::scope_scan::integrity::unreadable_key(kind(item.position.kind)?);
        if item.child.is_some()
            || item.claim.is_some()
            || item.stored_bytes != 0
            || inspection.disposition != expected.disposition
            || inspection.failures != expected.failures
            || inspection.inventory_incomplete != expected.inventory_incomplete
        {
            return Err(ScopeScanWireError);
        }
    }
    if inspection.failures.len() > 8
        || inspection
            .failures
            .iter()
            .enumerate()
            .any(|(n, f)| inspection.failures[..n].contains(f))
        || inspection.inventory_incomplete
            != inspection.failures.iter().any(|failure| {
                matches!(
                    failure,
                    ItemFailure::Corrupt {
                        kind: ItemKind::Claim,
                        key: None,
                        ..
                    }
                )
            })
    {
        return Err(ScopeScanWireError);
    }
    let good = inspection.failures.is_empty() && !inspection.inventory_incomplete;
    let valid=match inspection.disposition {
        ItemDisposition::LiveChild=>item.position.kind==0 && good && item.child.as_ref().is_some_and(|child|child.value().is_some() && child.batch_revision<=cut.batch_revision),
        ItemDisposition::ChildTombstone=>item.position.kind==0 && good && item.child.as_ref().is_some_and(|child|child.value().is_none() && child.batch_revision<=cut.batch_revision),
        ItemDisposition::UnrestorableChild=>item.position.kind==0 && !inspection.failures.is_empty(),
        ItemDisposition::ClaimHeld(holder)=>item.position.kind==1 && good && item.claim.as_ref().is_some_and(|claim|claim.revision<=cut.batch_revision && claim.owner.is_some_and(|owner|*owner.child.as_bytes()==holder.child && owner.birth==holder.birth)),
        ItemDisposition::ClaimHeldUnknown=>item.position.kind==1 && !inspection.failures.is_empty(),
        ItemDisposition::ClaimReleased=>item.position.kind==1 && good && item.claim.as_ref().is_some_and(|claim|claim.owner.is_none() && claim.revision<=cut.batch_revision),
        ItemDisposition::MissingAtCut=>item.child.is_none() && item.claim.is_none() && inspection.failures.iter().any(|failure|matches!(failure,ItemFailure::Missing{kind,key} if kind_tag(*kind)==item.position.kind && item.position.logical_key()==Some(key.as_slice()))),
    };
    if !valid {
        return Err(ScopeScanWireError);
    }
    Ok(())
}
pub(super) fn write(
    w: &mut Writer,
    cut: &ScopeCut,
    item: &InspectedItem,
    memory: &mut Memory,
) -> Result<(), ScopeScanWireError> {
    valid_item(cut, item)?;
    let maximum = if item.position.kind == 0 {
        scope_storage::MAX_SCOPE_ROW_BYTES
    } else {
        scope_storage::MAX_METADATA_BYTES
    };
    if item.stored_bytes > maximum {
        return Err(ScopeScanWireError);
    }
    memory.add(item.stored_bytes)?;
    w.u8(item.position.kind)?;
    w.u8(item.position.locator as u8)?;
    w.u8(item.position.bytes.len() as u8)?;
    w.put(&item.position.bytes)?;
    write_disposition(w, item.inspection.disposition)?;
    w.u8(u8::from(item.inspection.inventory_incomplete))?;
    w.u8(item.inspection.failures.len() as u8)?;
    for failure in &item.inspection.failures {
        write_failure(w, *failure)?;
    }
    let body = match (&item.child, &item.claim) {
        (Some(child), None) => Some((
            1,
            ScopeRow::Child(child.clone())
                .inventory_body()
                .map_err(|_| ScopeScanWireError)?,
        )),
        (None, Some(claim)) => Some((
            2,
            ScopeRow::Claim(claim.clone())
                .inventory_body()
                .map_err(|_| ScopeScanWireError)?,
        )),
        (None, None) => None,
        _ => return Err(ScopeScanWireError),
    };
    if let Some((tag, bytes)) = body {
        if bytes.len() != item.stored_bytes {
            return Err(ScopeScanWireError);
        }
        w.u8(tag)?;
        w.bytes_u32(&bytes, maximum)
    } else {
        if item.stored_bytes != 0 {
            return Err(ScopeScanWireError);
        }
        w.u8(0)
    }
}
pub(super) fn read(
    r: &mut Reader<'_>,
    cut: &ScopeCut,
    memory: &mut Memory,
) -> Result<InspectedItem, ScopeScanWireError> {
    let kind = r.u8()?;
    let locator = LocatorKind::decode(r.u8()?).ok_or(ScopeScanWireError)?;
    let length = usize::from(r.u8()?);
    if !locator.accepts_length(length) {
        return Err(ScopeScanWireError);
    }
    let position = InventoryPosition {
        kind,
        locator,
        bytes: r.take(length)?.to_vec(),
    };
    valid_position(cut, &position)?;
    let disposition = read_disposition(r)?;
    let inventory_incomplete = r.boolean()?;
    let count = usize::from(r.u8()?);
    if count > 8 || count > r.remaining() / 4 {
        return Err(ScopeScanWireError);
    }
    let mut failures = Vec::with_capacity(count);
    for _ in 0..count {
        failures.push(read_failure(r)?);
    }
    let maximum = if kind == 0 {
        scope_storage::MAX_SCOPE_ROW_BYTES
    } else {
        scope_storage::MAX_METADATA_BYTES
    };
    let body_tag = r.u8()?;
    let mut child = None;
    let mut claim = None;
    let stored_bytes;
    match body_tag {
        0 => {
            stored_bytes = 0;
            memory.add(0)?;
        }
        1 | 2 => {
            let bytes = r.bytes_u32(maximum)?;
            stored_bytes = bytes.len();
            memory.add(stored_bytes)?;
            match ScopeRow::from_inventory_body(bytes).map_err(|_| ScopeScanWireError)? {
                ScopeRow::Child(row) if body_tag == 1 && kind == 0 => child = Some(row),
                ScopeRow::Claim(row) if body_tag == 2 && kind == 1 => claim = Some(row),
                _ => return Err(ScopeScanWireError),
            }
        }
        _ => return Err(ScopeScanWireError),
    }
    let item = InspectedItem {
        position,
        child,
        claim,
        inspection: FinalItemInspection {
            disposition,
            failures,
            inventory_incomplete,
        },
        stored_bytes,
    };
    valid_item(cut, &item)?;
    Ok(item)
}
