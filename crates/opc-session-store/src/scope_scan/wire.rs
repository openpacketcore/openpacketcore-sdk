//! Bounded observation envelopes for authenticated scan transports.

use super::codec::{Reader, Writer};
use super::protocol::ReplyBody;
use super::*;
use crate::scope_authority::{ScopeAuthorityStamp, ScopeAuthorityView};
use crate::SessionConsensusNodeId;
use std::{fmt, sync::Arc};
mod errors;
mod items;
mod values;

/// Maximum encoded request, including a bounded original succession claim.
pub const MAX_SCOPE_SCAN_REQUEST_BYTES: usize = MAX_SCOPE_SCAN_OPEN_BYTES + 2;
/// Maximum encoded response body, leaving transport result-envelope headroom.
pub const MAX_SCOPE_SCAN_REPLY_BYTES: usize = 2 * 1024 * 1024 - 512;

/// Read-only opening observations. Decoding never grants mutation authority.
#[derive(Clone)]
pub struct ScopeScanOpenReply {
    pub(crate) cut: ScopeCut,
    pub(crate) authority: ScopeAuthorityView,
    pub(crate) checkpoint: ScopeScanCheckpoint,
    pub(crate) initial_cursor: ScopeScanCursor,
}
impl From<&ScopeRestoreView> for ScopeScanOpenReply {
    fn from(view: &ScopeRestoreView) -> Self {
        Self {
            cut: view.cut().clone(),
            authority: view.authority().clone(),
            checkpoint: view.checkpoint().clone(),
            initial_cursor: view.initial_cursor().clone(),
        }
    }
}
impl ScopeScanClientView for ScopeScanOpenReply {
    fn cut(&self) -> &ScopeCut {
        &self.cut
    }
    fn authority(&self) -> &ScopeAuthorityView {
        &self.authority
    }
    fn checkpoint(&self) -> &ScopeScanCheckpoint {
        &self.checkpoint
    }
    fn initial_cursor(&self) -> &ScopeScanCursor {
        &self.initial_cursor
    }
}
impl fmt::Debug for ScopeScanOpenReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeScanOpenReply(<redacted>)")
    }
}

/// Untrusted routing claims for one node-local view; every call reauthenticates.
#[derive(Clone)]
pub struct ScopeScanViewToken {
    pub(crate) stamp: ScopeAuthorityStamp,
    pub(crate) serving_node: SessionConsensusNodeId,
    pub(crate) capture_id: [u8; 16],
}
impl ScopeScanViewToken {
    /// Bind current successor claims to an observed capture. This creates no capability.
    pub fn new(stamp: &ScopeAuthorityStamp, cut: &ScopeCut) -> Result<Self, ScopeScanError> {
        if stamp.namespace() != cut.namespace() || stamp.revision() != cut.authority_revision() {
            return Err(ScopeScanError::Unauthorized);
        }
        Ok(Self {
            stamp: stamp.clone(),
            serving_node: cut.serving_node,
            capture_id: cut.capture_id,
        })
    }
    /// Exact successor claimed by this call.
    pub fn stamp(&self) -> &ScopeAuthorityStamp {
        &self.stamp
    }
    /// Node retaining this capture.
    pub const fn serving_node(&self) -> SessionConsensusNodeId {
        self.serving_node
    }
    /// Opaque process-local capture identifier; possession is never authorization.
    pub const fn capture_id(&self) -> &[u8; 16] {
        &self.capture_id
    }
}
impl fmt::Debug for ScopeScanViewToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeScanViewToken(<redacted>)")
    }
}

/// One bounded request, interpreted only inside authenticated own-boot admission.
#[derive(Clone, Debug)]
pub enum ScopeScanRequest {
    /// Open a positively handed-over coherent cut.
    Open(Box<ScopeScanOpenRequest>),
    /// Fetch or replay the exact input cursor.
    Page {
        /// Reauthenticated routing claims.
        view: ScopeScanViewToken,
        /// Opaque continuation for this capture.
        cursor: ScopeScanCursor,
    },
    /// Read one child or claim using the Normal budget.
    Lookup {
        /// Reauthenticated routing claims.
        view: ScopeScanViewToken,
        /// Exact logical child or claim.
        key: ScopeScanLookupKey,
    },
    /// Read one item using the fixed Emergency classification budget.
    Classify {
        /// Reauthenticated routing claims.
        view: ScopeScanViewToken,
        /// Exact logical child or claim.
        key: ScopeScanLookupKey,
    },
    /// Revoke and drain this capture.
    Close(ScopeScanViewToken),
}
impl ScopeScanRequest {
    /// Exact successor claims to bind to current boot proof on every operation.
    pub fn stamp(&self) -> &ScopeAuthorityStamp {
        match self {
            Self::Open(open) => open.stamp(),
            Self::Page { view, .. }
            | Self::Lookup { view, .. }
            | Self::Classify { view, .. }
            | Self::Close(view) => view.stamp(),
        }
    }
    /// Canonical bounded request bytes.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, ScopeScanWireError> {
        let mut w = Writer::new(MAX_SCOPE_SCAN_REQUEST_BYTES);
        w.u8(1)?;
        match self {
            Self::Open(open) => {
                w.u8(1)?;
                w.put(&open.encode_canonical()?)?;
            }
            Self::Page { view, cursor } => {
                w.u8(2)?;
                values::write_token(&mut w, view)?;
                values::write_cursor(&mut w, cursor)?;
            }
            Self::Lookup { view, key } | Self::Classify { view, key } => {
                w.u8(if matches!(self, Self::Lookup { .. }) {
                    3
                } else {
                    4
                })?;
                values::write_token(&mut w, view)?;
                values::write_lookup_key(&mut w, *key)?;
            }
            Self::Close(view) => {
                w.u8(5)?;
                values::write_token(&mut w, view)?;
            }
        }
        Ok(w.finish())
    }
    /// Decode claims without authorizing or opening a retained view.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ScopeScanWireError> {
        let mut r = Reader::new(bytes, MAX_SCOPE_SCAN_REQUEST_BYTES)?;
        if r.u8()? != 1 {
            return Err(ScopeScanWireError);
        }
        let value = match r.u8()? {
            1 => {
                let remaining = r.remaining();
                Self::Open(Box::new(ScopeScanOpenRequest::decode_canonical(
                    r.take(remaining)?,
                )?))
            }
            2 => Self::Page {
                view: values::read_token(&mut r)?,
                cursor: values::read_cursor(&mut r)?,
            },
            3 => Self::Lookup {
                view: values::read_token(&mut r)?,
                key: values::read_lookup_key(&mut r)?,
            },
            4 => Self::Classify {
                view: values::read_token(&mut r)?,
                key: values::read_lookup_key(&mut r)?,
            },
            5 => Self::Close(values::read_token(&mut r)?),
            _ => return Err(ScopeScanWireError),
        };
        r.finish()?;
        Ok(value)
    }
}

/// One bounded response; the authenticated transport binds it to its request.
#[derive(Debug)]
pub enum ScopeScanResponse {
    /// Coherent opening observations and initial continuation.
    Open(ScopeScanOpenReply),
    /// Exact cached inventory or failure-manifest page.
    Page(Arc<ScopeScanReply>),
    /// Final point result from the same cut.
    Lookup(ScopeScanLookup),
    /// Explicit close completed; no retained view remains.
    Closed,
    /// Typed final or retryable operation failure.
    Failure(ScopeScanRequestFailure),
}
impl ScopeScanResponse {
    /// Encode within the fixed reply frame; page limits must be selected before open.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, ScopeScanWireError> {
        let mut w = Writer::new(MAX_SCOPE_SCAN_REPLY_BYTES);
        w.u8(1)?;
        match self {
            Self::Open(open) => {
                w.u8(1)?;
                values::write_open(&mut w, open)?;
            }
            Self::Page(reply) => {
                w.u8(2)?;
                values::write_cut(&mut w, &reply.cut)?;
                match &reply.body {
                    ReplyBody::Data { items, next } => {
                        if items.len() > crate::RESTORE_SCAN_MAX_PAGE_SIZE
                            || items
                                .windows(2)
                                .any(|pair| pair[0].position >= pair[1].position)
                        {
                            return Err(ScopeScanWireError);
                        }
                        w.u8(0)?;
                        w.u16(items.len() as u16)?;
                        let mut memory = items::Memory::new();
                        for item in items {
                            items::write(&mut w, &reply.cut, item, &mut memory)?;
                        }
                        values::write_cursor(&mut w, next)?;
                    }
                    ReplyBody::WorkBudget { next } => {
                        w.u8(1)?;
                        values::write_cursor(&mut w, next)?;
                    }
                    ReplyBody::Complete { totals, manifest } => {
                        w.u8(2)?;
                        values::write_totals(&mut w, *totals)?;
                        w.u8(u8::from(manifest.is_some()))?;
                        if let Some(manifest) = manifest {
                            values::write_cursor(&mut w, manifest)?;
                        }
                    }
                }
            }
            Self::Lookup(lookup) => {
                w.u8(3)?;
                values::write_cut(&mut w, &lookup.cut)?;
                items::write(&mut w, &lookup.cut, &lookup.item, &mut items::Memory::new())?;
            }
            Self::Closed => w.u8(4)?,
            Self::Failure(failure) => {
                w.u8(5)?;
                errors::write(&mut w, *failure)?;
            }
        }
        Ok(w.finish())
    }
    /// Bound every count and nested row before allocating owned observation data.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ScopeScanWireError> {
        let mut r = Reader::new(bytes, MAX_SCOPE_SCAN_REPLY_BYTES)?;
        if r.u8()? != 1 {
            return Err(ScopeScanWireError);
        }
        let value = match r.u8()? {
            1 => Self::Open(values::read_open(&mut r)?),
            2 => {
                let cut = values::read_cut(&mut r)?;
                let body = match r.u8()? {
                    0 => {
                        let count = usize::from(r.u16()?);
                        // The shortest malformed native locator plus its required
                        // final unknown-key failure needs twelve bytes.
                        if count > crate::RESTORE_SCAN_MAX_PAGE_SIZE || count > r.remaining() / 12 {
                            return Err(ScopeScanWireError);
                        }
                        let mut items = Vec::<super::engine::InspectedItem>::with_capacity(count);
                        let mut memory = items::Memory::new();
                        for _ in 0..count {
                            let item = items::read(&mut r, &cut, &mut memory)?;
                            if items
                                .last()
                                .is_some_and(|previous| previous.position >= item.position)
                            {
                                return Err(ScopeScanWireError);
                            }
                            items.push(item);
                        }
                        ReplyBody::Data {
                            items,
                            next: values::read_cursor(&mut r)?,
                        }
                    }
                    1 => ReplyBody::WorkBudget {
                        next: values::read_cursor(&mut r)?,
                    },
                    2 => {
                        let totals = values::read_totals(&mut r)?;
                        let manifest = if r.boolean()? {
                            Some(values::read_cursor(&mut r)?)
                        } else {
                            None
                        };
                        ReplyBody::Complete { totals, manifest }
                    }
                    _ => return Err(ScopeScanWireError),
                };
                Self::Page(Arc::new(ScopeScanReply { cut, body }))
            }
            3 => {
                let cut = values::read_cut(&mut r)?;
                let item = items::read(&mut r, &cut, &mut items::Memory::new())?;
                Self::Lookup(ScopeScanLookup { cut, item })
            }
            4 => Self::Closed,
            5 => Self::Failure(errors::read(&mut r)?),
            _ => return Err(ScopeScanWireError),
        };
        r.finish()?;
        Ok(value)
    }
}

impl ScopeScanPageLimits {
    /// Reserve worst-case metadata and framing before capturing a remote page.
    /// A legal maximum-size child still fits; this never caps total inventory.
    pub fn for_transport(self, maximum_reply_bytes: usize) -> Result<Self, ScopeScanError> {
        Self::new(self.rows(), self.payload_bytes())?;
        if maximum_reply_bytes > MAX_SCOPE_SCAN_REPLY_BYTES {
            return Err(ScopeScanError::InvalidPageLimits);
        }
        // One cut, framing and continuation fit 16 KiB. A position, holder and
        // all eight final failures fit 512 bytes per item, excluding its body.
        let overhead = self
            .rows()
            .checked_mul(512)
            .and_then(|n| n.checked_add(16 * 1024))
            .ok_or(ScopeScanError::InvalidPageLimits)?;
        let payload = maximum_reply_bytes
            .checked_sub(overhead)
            .ok_or(ScopeScanError::InvalidPageLimits)?;
        Self::new(self.rows(), self.payload_bytes().min(payload))
    }
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;
