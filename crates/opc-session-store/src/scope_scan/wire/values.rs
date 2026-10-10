//! Fixed-size cut, header, cursor and routing observations.

use super::*;
use crate::scope_authority::{
    ScopeId, ScopeIncarnation, ScopeNamespace, MAX_SCOPE_AUTHORITY_RECORD_BYTES,
};
use crate::scope_batch::{ScopeChildKey, ScopeClaimKey};
use crate::scope_scan::codec::{Reader, Writer};
use crate::scope_scan::progress::InventoryTotals;

pub(super) fn write_stamp(
    w: &mut Writer,
    stamp: &ScopeAuthorityStamp,
) -> Result<(), ScopeScanWireError> {
    w.bytes_u16(
        &stamp.encode_canonical().map_err(|_| ScopeScanWireError)?,
        MAX_SCOPE_AUTHORITY_RECORD_BYTES,
    )
}
pub(super) fn read_stamp(r: &mut Reader<'_>) -> Result<ScopeAuthorityStamp, ScopeScanWireError> {
    ScopeAuthorityStamp::decode_canonical(r.bytes_u16(MAX_SCOPE_AUTHORITY_RECORD_BYTES)?)
        .map_err(|_| ScopeScanWireError)
}
pub(super) fn write_token(
    w: &mut Writer,
    token: &ScopeScanViewToken,
) -> Result<(), ScopeScanWireError> {
    if token.capture_id == [0; 16] {
        return Err(ScopeScanWireError);
    }
    write_stamp(w, &token.stamp)?;
    w.u64(token.serving_node.get())?;
    w.put(&token.capture_id)
}
pub(super) fn read_token(r: &mut Reader<'_>) -> Result<ScopeScanViewToken, ScopeScanWireError> {
    let token = ScopeScanViewToken {
        stamp: read_stamp(r)?,
        serving_node: SessionConsensusNodeId::new(r.u64()?).map_err(|_| ScopeScanWireError)?,
        capture_id: r.array()?,
    };
    if token.capture_id == [0; 16] {
        return Err(ScopeScanWireError);
    }
    Ok(token)
}
pub(super) fn write_cursor(
    w: &mut Writer,
    cursor: &ScopeScanCursor,
) -> Result<(), ScopeScanWireError> {
    w.bytes_u16(cursor.as_bytes(), 256)
}
pub(super) fn read_cursor(r: &mut Reader<'_>) -> Result<ScopeScanCursor, ScopeScanWireError> {
    ScopeScanCursor::from_bytes(r.bytes_u16(256)?).map_err(|_| ScopeScanWireError)
}
pub(super) fn write_lookup_key(
    w: &mut Writer,
    key: ScopeScanLookupKey,
) -> Result<(), ScopeScanWireError> {
    match key {
        ScopeScanLookupKey::Child(key) => {
            w.u8(0)?;
            w.put(key.as_bytes())
        }
        ScopeScanLookupKey::Claim(key) => {
            w.u8(1)?;
            w.put(key.as_bytes())
        }
    }
}
pub(super) fn read_lookup_key(
    r: &mut Reader<'_>,
) -> Result<ScopeScanLookupKey, ScopeScanWireError> {
    let kind = r.u8()?;
    let key = r.array()?;
    match kind {
        0 => ScopeChildKey::new(key)
            .map(ScopeScanLookupKey::Child)
            .map_err(|_| ScopeScanWireError),
        1 => ScopeClaimKey::new(key)
            .map(ScopeScanLookupKey::Claim)
            .map_err(|_| ScopeScanWireError),
        _ => Err(ScopeScanWireError),
    }
}
fn valid_cut(cut: &ScopeCut) -> Result<(), ScopeScanWireError> {
    if cut.authority_revision == 0
        || cut.authority_revision > i64::MAX as u64
        || cut.batch_revision > i64::MAX as u64
        || cut.epoch == 0
        || cut.capture_id == [0; 16]
    {
        return Err(ScopeScanWireError);
    }
    Ok(())
}
pub(super) fn write_cut(w: &mut Writer, cut: &ScopeCut) -> Result<(), ScopeScanWireError> {
    valid_cut(cut)?;
    w.bytes_u16(
        &cut.namespace
            .scope()
            .encode_canonical()
            .map_err(|_| ScopeScanWireError)?,
        MAX_SCOPE_AUTHORITY_RECORD_BYTES,
    )?;
    w.u64(cut.namespace.incarnation().get())?;
    w.u64(cut.authority_revision)?;
    w.u64(cut.batch_revision)?;
    // Bind the complete SDK LogId in its existing canonical representation.
    // The configured single-term-leader type has no independent leader node field.
    w.bytes_u16(
        &postcard::to_allocvec(&cut.applied).map_err(|_| ScopeScanWireError)?,
        32,
    )?;
    w.u64(cut.epoch)?;
    w.put(&cut.capture_id)?;
    w.u64(cut.serving_node.get())
}
pub(super) fn read_cut(r: &mut Reader<'_>) -> Result<ScopeCut, ScopeScanWireError> {
    let scope = ScopeId::decode_canonical(r.bytes_u16(MAX_SCOPE_AUTHORITY_RECORD_BYTES)?)
        .map_err(|_| ScopeScanWireError)?;
    let incarnation = ScopeIncarnation::new(r.u64()?).map_err(|_| ScopeScanWireError)?;
    let namespace = ScopeNamespace::new(scope, incarnation).map_err(|_| ScopeScanWireError)?;
    let authority_revision = r.u64()?;
    let batch_revision = r.u64()?;
    let bytes = r.bytes_u16(32)?;
    let (applied, trailing): (opc_consensus::engine::LogId<SessionConsensusNodeId>, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| ScopeScanWireError)?;
    if !trailing.is_empty()
        || postcard::to_allocvec(&applied).map_err(|_| ScopeScanWireError)? != bytes
    {
        return Err(ScopeScanWireError);
    }
    let cut = ScopeCut {
        namespace,
        authority_revision,
        batch_revision,
        applied,
        epoch: r.u64()?,
        capture_id: r.array()?,
        serving_node: SessionConsensusNodeId::new(r.u64()?).map_err(|_| ScopeScanWireError)?,
    };
    valid_cut(&cut)?;
    Ok(cut)
}
fn valid_open(open: &ScopeScanOpenReply) -> Result<(), ScopeScanWireError> {
    let stamp = open.authority.stamp().ok_or(ScopeScanWireError)?;
    if !open.authority.is_active()
        || stamp.namespace() != open.cut.namespace()
        || stamp.revision() != open.cut.authority_revision()
        || open.checkpoint.revision != open.cut.batch_revision
        || open.checkpoint.birth_floor > i64::MAX as u64
        || open
            .checkpoint
            .counters
            .iter()
            .any(|value| *value > i64::MAX as u64)
        || (open.checkpoint.revision == 0
            && (open.checkpoint.birth_floor != 0 || open.checkpoint.counters != [0; 16]))
    {
        return Err(ScopeScanWireError);
    }
    Ok(())
}
pub(super) fn write_open(
    w: &mut Writer,
    open: &ScopeScanOpenReply,
) -> Result<(), ScopeScanWireError> {
    valid_open(open)?;
    write_cut(w, &open.cut)?;
    w.bytes_u16(
        &open
            .authority
            .encode_canonical()
            .map_err(|_| ScopeScanWireError)?,
        MAX_SCOPE_AUTHORITY_RECORD_BYTES,
    )?;
    w.u64(open.checkpoint.revision)?;
    w.u64(open.checkpoint.birth_floor)?;
    for counter in open.checkpoint.counters {
        w.u64(counter)?;
    }
    write_cursor(w, &open.initial_cursor)
}
pub(super) fn read_open(r: &mut Reader<'_>) -> Result<ScopeScanOpenReply, ScopeScanWireError> {
    let cut = read_cut(r)?;
    let authority =
        ScopeAuthorityView::decode_canonical(r.bytes_u16(MAX_SCOPE_AUTHORITY_RECORD_BYTES)?)
            .map_err(|_| ScopeScanWireError)?;
    let revision = r.u64()?;
    let birth_floor = r.u64()?;
    let mut counters = [0; 16];
    for counter in &mut counters {
        *counter = r.u64()?;
    }
    let checkpoint = ScopeScanCheckpoint {
        revision,
        birth_floor,
        counters,
    };
    let initial_cursor = read_cursor(r)?;
    let open = ScopeScanOpenReply {
        cut,
        authority,
        checkpoint,
        initial_cursor,
    };
    valid_open(&open)?;
    Ok(open)
}
fn valid_totals(totals: InventoryTotals) -> Result<(), ScopeScanWireError> {
    if totals.failed_items > totals.items
        || totals.failures < totals.failed_items
        || totals.failures > totals.failed_items.saturating_mul(8)
        || (totals.claims_incomplete && totals.failed_items == 0)
    {
        return Err(ScopeScanWireError);
    }
    Ok(())
}
pub(super) fn write_totals(
    w: &mut Writer,
    totals: InventoryTotals,
) -> Result<(), ScopeScanWireError> {
    valid_totals(totals)?;
    w.u64(totals.items)?;
    w.u64(totals.failed_items)?;
    w.u64(totals.failures)?;
    w.u8(u8::from(totals.claims_incomplete))
}
pub(super) fn read_totals(r: &mut Reader<'_>) -> Result<InventoryTotals, ScopeScanWireError> {
    let totals = InventoryTotals {
        items: r.u64()?,
        failed_items: r.u64()?,
        failures: r.u64()?,
        claims_incomplete: r.boolean()?,
    };
    valid_totals(totals)?;
    Ok(totals)
}
