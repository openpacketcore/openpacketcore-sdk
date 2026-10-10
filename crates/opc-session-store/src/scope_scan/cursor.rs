//! Confidential continuations for one retained, authenticated view.

use super::engine::InventoryPosition;
use super::progress::{InventoryTotals, PageLimits};
use super::{ScopeCut, ScopeScanError};
use crate::scope_authority::ScopeAuthorityStamp;
use aes_gcm_siv::{
    aead::{AeadInOut, KeyInit},
    Aes256GcmSiv,
};
use opc_key::Zeroizing;
use rand::{rngs::SysRng, TryRng};
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc};

use super::position::LocatorKind;

const VERSION: u8 = 1;
const MIN_BYTES: usize = 98;
const MAX_BYTES: usize = 256;
const DOMAIN: &[u8] = b"openpacketcore/scope-scan/cursor/v1\0";

/// Opaque continuation. Possession grants no mutation or restore authority.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopeScanCursor(Arc<[u8]>);
impl ScopeScanCursor {
    /// Import a bounded envelope. Authentication occurs against its live view.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ScopeScanError> {
        if !(MIN_BYTES..=MAX_BYTES).contains(&bytes.len()) || bytes.first() != Some(&VERSION) {
            return Err(ScopeScanError::InvalidCursor);
        }
        Ok(Self(Arc::from(bytes)))
    }
    /// Opaque transport bytes; do not interpret the continuation as authority.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for ScopeScanCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeScanCursor(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CursorPhase {
    Inventory,
    InventoryFinalize,
    Manifest,
    ManifestFinalize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CursorState {
    pub(crate) phase: CursorPhase,
    pub(crate) attempt: u64,
    pub(crate) rows: usize,
    pub(crate) after: Option<InventoryPosition>,
    pub(crate) totals: InventoryTotals,
}

pub(crate) struct CursorCodec {
    key: Zeroizing<[u8; 32]>,
    binding: [u8; 32],
    limits: PageLimits,
}
impl CursorCodec {
    pub(crate) fn new(
        cut: &ScopeCut,
        stamp: &ScopeAuthorityStamp,
        limits: PageLimits,
    ) -> Result<Self, ScopeScanError> {
        let mut key = Zeroizing::new([0; 32]);
        SysRng
            .try_fill_bytes(&mut *key)
            .map_err(|_| ScopeScanError::Unavailable)?;
        Ok(Self {
            key,
            binding: binding(cut, stamp, limits)?,
            limits,
        })
    }
    pub(crate) fn seal(&self, state: &CursorState) -> Result<ScopeScanCursor, ScopeScanError> {
        self.validate(state)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(MAX_BYTES - 29));
        plaintext.extend_from_slice(&self.binding);
        plaintext.push(match state.phase {
            CursorPhase::Inventory => 0,
            CursorPhase::InventoryFinalize => 1,
            CursorPhase::Manifest => 2,
            CursorPhase::ManifestFinalize => 3,
        });
        plaintext.extend_from_slice(&state.attempt.to_be_bytes());
        plaintext.extend_from_slice(&(state.rows as u16).to_be_bytes());
        if let Some(after) = &state.after {
            plaintext.push(1);
            plaintext.push(after.kind);
            plaintext.push(after.locator as u8);
            plaintext.push(after.bytes.len() as u8);
            plaintext.extend_from_slice(&after.bytes);
        } else {
            plaintext.push(0);
        }
        plaintext.extend_from_slice(&state.totals.items.to_be_bytes());
        plaintext.extend_from_slice(&state.totals.failed_items.to_be_bytes());
        plaintext.extend_from_slice(&state.totals.failures.to_be_bytes());
        plaintext.push(u8::from(state.totals.claims_incomplete));
        let mut nonce = [0; 12];
        SysRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| ScopeScanError::Unavailable)?;
        let cipher = Aes256GcmSiv::new((&*self.key).into());
        let tag = cipher
            .encrypt_inout_detached((&nonce).into(), DOMAIN, plaintext.as_mut_slice().into())
            .map_err(|_| ScopeScanError::Unavailable)?;
        let mut token = Vec::with_capacity(29 + plaintext.len());
        token.push(VERSION);
        token.extend_from_slice(&nonce);
        token.extend_from_slice(&plaintext);
        token.extend_from_slice(tag.as_slice());
        ScopeScanCursor::from_bytes(&token)
    }
    pub(crate) fn open(&self, cursor: &ScopeScanCursor) -> Result<CursorState, ScopeScanError> {
        let bytes = cursor.as_bytes();
        if !(MIN_BYTES..=MAX_BYTES).contains(&bytes.len()) || bytes[0] != VERSION {
            return Err(ScopeScanError::InvalidCursor);
        }
        let nonce: &[u8; 12] = bytes[1..13]
            .try_into()
            .map_err(|_| ScopeScanError::InvalidCursor)?;
        let tag_start = bytes.len() - 16;
        let tag: &[u8; 16] = bytes[tag_start..]
            .try_into()
            .map_err(|_| ScopeScanError::InvalidCursor)?;
        // The envelope bound precedes this owned copy. Decrypted positions are
        // erased on every return, including authentication and parse failures.
        let mut plaintext = Zeroizing::new(bytes[13..tag_start].to_vec());
        let cipher = Aes256GcmSiv::new((&*self.key).into());
        cipher
            .decrypt_inout_detached(
                nonce.into(),
                DOMAIN,
                plaintext.as_mut_slice().into(),
                tag.into(),
            )
            .map_err(|_| ScopeScanError::InvalidCursor)?;
        let mut input = Input(&plaintext);
        if input.take::<32>()? != self.binding {
            return Err(ScopeScanError::InvalidCursor);
        }
        let phase = match input.byte()? {
            0 => CursorPhase::Inventory,
            1 => CursorPhase::InventoryFinalize,
            2 => CursorPhase::Manifest,
            3 => CursorPhase::ManifestFinalize,
            _ => return Err(ScopeScanError::InvalidCursor),
        };
        let attempt = u64::from_be_bytes(input.take()?);
        let rows = usize::from(u16::from_be_bytes(input.take()?));
        let after = if input.boolean()? {
            let kind = input.byte()?;
            let locator =
                LocatorKind::decode(input.byte()?).ok_or(ScopeScanError::InvalidCursor)?;
            let len = usize::from(input.byte()?);
            if kind > 1 || !locator.accepts_length(len) {
                return Err(ScopeScanError::InvalidCursor);
            }
            Some(InventoryPosition {
                kind,
                locator,
                bytes: input.bytes(len)?.to_vec(),
            })
        } else {
            None
        };
        let totals = InventoryTotals {
            items: u64::from_be_bytes(input.take()?),
            failed_items: u64::from_be_bytes(input.take()?),
            failures: u64::from_be_bytes(input.take()?),
            claims_incomplete: input.boolean()?,
        };
        if !input.0.is_empty() {
            return Err(ScopeScanError::InvalidCursor);
        }
        let state = CursorState {
            phase,
            attempt,
            rows,
            after,
            totals,
        };
        self.validate(&state)?;
        Ok(state)
    }
    fn validate(&self, state: &CursorState) -> Result<(), ScopeScanError> {
        let totals = state.totals;
        if !(1..=self.limits.rows.min(1024)).contains(&state.rows)
            || state
                .after
                .as_ref()
                .is_some_and(|after| !after.valid_shape())
            || totals.failed_items > totals.items
            || totals.failures < totals.failed_items
            || totals.failures > totals.failed_items.saturating_mul(8)
            || (totals.claims_incomplete && totals.failed_items == 0)
        {
            return Err(ScopeScanError::InvalidCursor);
        }
        Ok(())
    }
}
struct Input<'a>(&'a [u8]);
impl<'a> Input<'a> {
    fn bytes(&mut self, count: usize) -> Result<&'a [u8], ScopeScanError> {
        let (head, tail) = self
            .0
            .split_at_checked(count)
            .ok_or(ScopeScanError::InvalidCursor)?;
        self.0 = tail;
        Ok(head)
    }
    fn take<const N: usize>(&mut self) -> Result<[u8; N], ScopeScanError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| ScopeScanError::InvalidCursor)
    }
    fn byte(&mut self) -> Result<u8, ScopeScanError> {
        Ok(self.take::<1>()?[0])
    }
    fn boolean(&mut self) -> Result<bool, ScopeScanError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ScopeScanError::InvalidCursor),
        }
    }
}
fn binding(
    cut: &ScopeCut,
    stamp: &ScopeAuthorityStamp,
    limits: PageLimits,
) -> Result<[u8; 32], ScopeScanError> {
    let bytes = postcard::to_allocvec(&(
        &cut.namespace,
        cut.authority_revision,
        cut.batch_revision,
        cut.applied,
        cut.epoch,
        cut.capture_id,
        cut.serving_node,
        stamp,
        limits.rows as u64,
        limits.payload_bytes as u64,
        limits.retained_bytes as u64,
        limits.visits as u64,
        limits.metadata_bytes as u64,
    ))
    .map_err(|_| ScopeScanError::Unavailable)?;
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(bytes);
    Ok(digest.finalize().into())
}

#[cfg(test)]
#[path = "cursor_tests.rs"]
mod tests;
