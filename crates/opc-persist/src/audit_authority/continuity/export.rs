use super::{
    chain::{verify_row, SignedAuditRow},
    AuditKeyRing,
};
use crate::audit_authority::ledger::{
    authenticate, verify, LedgerEntry, LedgerState, MAX_STATE_BYTES,
};
use crate::audit_authority::{AuditAuthorityError, AuditCaller};
use crate::ConfigConsensusIdentity;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const MANIFEST_DOMAIN: &[u8] = b"openpacketcore/management-audit/export-manifest/v1\0";
const CURSOR_DOMAIN: &[u8] = b"openpacketcore/management-audit/export-cursor/v1\0";
const MAX_PAGE_ROWS: usize = 256;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestBody {
    pub(crate) version: u16,
    pub(crate) identity: ConfigConsensusIdentity,
    pub(crate) recipient: AuditCaller,
    pub(crate) floor: u64,
    pub(crate) predecessor: [u8; 32],
    pub(crate) floor_anchor: [u8; 32],
    pub(crate) floor_epoch: u64,
    pub(crate) sequence: u64,
    pub(crate) terminal: [u8; 32],
    pub(crate) anchor: [u8; 32],
    pub(crate) active_epoch: u64,
    pub(crate) row_count: usize,
    pub(crate) issued_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) nonce: [u8; 16],
}

/// Complete authenticated bounds for one immutable export, including its
/// retained predecessor, fleet, recipient, signing epochs and terminal anchor.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditExportManifest {
    pub(crate) body: ManifestBody,
    pub(crate) mac: [u8; 32],
}

macro_rules! opaque_encoding {
    ($ty:ty, $name:literal, $limit:expr) => {
        impl $ty {
            /// Encode only for an authorized export channel, never diagnostics.
            pub fn encode(&self) -> Result<Vec<u8>, AuditAuthorityError> {
                let encoded =
                    serde_json::to_vec(self).map_err(|_| AuditAuthorityError::InvalidInput)?;
                if encoded.len() > $limit {
                    return Err(AuditAuthorityError::InvalidInput);
                }
                Ok(encoded)
            }
            /// Decode bounded untrusted bytes; this is not verification.
            pub fn decode(bytes: &[u8]) -> Result<Self, AuditAuthorityError> {
                if bytes.len() > $limit {
                    return Err(AuditAuthorityError::InvalidInput);
                }
                serde_json::from_slice(bytes).map_err(|_| AuditAuthorityError::InvalidInput)
            }
        }
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str($name)
            }
        }
    };
}
opaque_encoding!(AuditExportManifest, "AuditExportManifest(<redacted>)", 8192);

fn live(issued: i64, expires: i64, now: i64) -> Result<(), AuditAuthorityError> {
    if now < issued || now >= expires {
        Err(AuditAuthorityError::Expired)
    } else {
        Ok(())
    }
}

impl AuditExportManifest {
    pub(crate) fn verify(
        &self,
        keys: &AuditKeyRing,
        identity: ConfigConsensusIdentity,
        recipient: AuditCaller,
        now: i64,
    ) -> Result<(), AuditAuthorityError> {
        let body = &self.body;
        if body.version != 1
            || body.identity != identity
            || body.recipient != recipient
            || body.sequence.checked_sub(body.floor) != Some(body.row_count as u64)
            || body.row_count > 4096
            || body
                .expires_at
                .checked_sub(body.issued_at)
                .is_none_or(|d| !(1..=3600).contains(&d))
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        verify(
            keys.key(body.active_epoch)?,
            MANIFEST_DOMAIN,
            body,
            &self.mac,
        )?;
        live(body.issued_at, body.expires_at, now)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorBody {
    manifest: [u8; 32],
    offset: usize,
}

/// Exact frozen-export offset, authenticated against the manifest. A cursor
/// from an earlier export cannot silently select a newer retained boundary.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditExportCursor {
    body: CursorBody,
    mac: [u8; 32],
}
opaque_encoding!(AuditExportCursor, "AuditExportCursor(<redacted>)", 4096);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportRow {
    entry: LedgerEntry,
    proof: SignedAuditRow,
}

/// Opaque projected rows for an authorized recipient. The SDK's streaming
/// verifier authenticates ordering, content, key transitions and completeness.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditExportPage {
    manifest: [u8; 32],
    offset: usize,
    rows: Vec<ExportRow>,
    next: Option<AuditExportCursor>,
}
opaque_encoding!(
    AuditExportPage,
    "AuditExportPage(<redacted>)",
    MAX_STATE_BYTES
);

impl AuditExportPage {
    /// Cursor for the next page; absence alone never proves export completeness.
    pub fn next_cursor(&self) -> Option<&AuditExportCursor> {
        self.next.as_ref()
    }
}

/// One fixed-expiry immutable snapshot. Local and replicated pruning cannot
/// change its pages. Dropping it releases its reserved export capacity.
pub struct AuditExportSession {
    manifest: AuditExportManifest,
    rows: Vec<ExportRow>,
    keys: Arc<AuditKeyRing>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl std::fmt::Debug for AuditExportSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditExportSession(<redacted>)")
    }
}

impl AuditExportSession {
    pub(crate) fn freeze(
        ledger: &LedgerState,
        keys: Arc<AuditKeyRing>,
        recipient: AuditCaller,
        now: i64,
        lifetime_seconds: u64,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<Self, AuditAuthorityError> {
        if !(1..=3600).contains(&lifetime_seconds) {
            return Err(AuditAuthorityError::InvalidInput);
        }
        ledger.validate_continuity(Some(&keys))?;
        let chain = ledger
            .continuity
            .as_ref()
            .ok_or(AuditAuthorityError::Unavailable)?;
        let body = ManifestBody {
            version: 1,
            identity: ledger.identity,
            recipient,
            floor: ledger.floor,
            predecessor: ledger.predecessor,
            floor_anchor: chain.floor_anchor,
            floor_epoch: chain.floor_epoch,
            sequence: ledger.sequence,
            terminal: ledger.terminal,
            anchor: chain.terminal,
            active_epoch: chain.active_epoch,
            row_count: ledger.entries.len(),
            issued_at: now,
            expires_at: now
                .checked_add(lifetime_seconds as i64)
                .ok_or(AuditAuthorityError::InvalidInput)?,
            nonce: *uuid::Uuid::new_v4().as_bytes(),
        };
        let mac = authenticate(keys.key(body.active_epoch)?, MANIFEST_DOMAIN, &body)?;
        let rows = ledger
            .entries
            .iter()
            .cloned()
            .zip(chain.rows.iter().cloned())
            .map(|(entry, proof)| ExportRow { entry, proof })
            .collect();
        Ok(Self {
            manifest: AuditExportManifest { body, mac },
            rows,
            keys,
            _permit: permit,
        })
    }

    /// Portable manifest. Recipients must verify it with their admitted key set.
    pub fn manifest(&self) -> &AuditExportManifest {
        &self.manifest
    }

    fn cursor(&self, offset: usize) -> Result<AuditExportCursor, AuditAuthorityError> {
        let body = CursorBody {
            manifest: self.manifest.mac,
            offset,
        };
        let mac = authenticate(
            self.keys.key(self.manifest.body.active_epoch)?,
            CURSOR_DOMAIN,
            &body,
        )?;
        Ok(AuditExportCursor { body, mac })
    }

    /// Read up to 256 rows with an exact authenticated cursor. `None` starts at
    /// this frozen manifest's boundary, not the live ledger's changing boundary.
    pub fn page(
        &self,
        cursor: Option<&AuditExportCursor>,
        max_rows: usize,
        recipient: AuditCaller,
    ) -> Result<AuditExportPage, AuditAuthorityError> {
        self.page_at(
            cursor,
            max_rows,
            recipient,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
    }

    pub(crate) fn page_at(
        &self,
        cursor: Option<&AuditExportCursor>,
        max_rows: usize,
        recipient: AuditCaller,
        now: i64,
    ) -> Result<AuditExportPage, AuditAuthorityError> {
        self.manifest
            .verify(&self.keys, self.manifest.body.identity, recipient, now)?;
        if !(1..=MAX_PAGE_ROWS).contains(&max_rows) {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let offset = if let Some(cursor) = cursor {
            if cursor.body.manifest != self.manifest.mac {
                return Err(AuditAuthorityError::BindingMismatch);
            }
            verify(
                self.keys.key(self.manifest.body.active_epoch)?,
                CURSOR_DOMAIN,
                &cursor.body,
                &cursor.mac,
            )?;
            cursor.body.offset
        } else {
            0
        };
        if offset > self.rows.len() {
            return Err(AuditAuthorityError::InvalidInput);
        }
        let end = offset.saturating_add(max_rows).min(self.rows.len());
        Ok(AuditExportPage {
            manifest: self.manifest.mac,
            offset,
            rows: self.rows[offset..end].to_vec(),
            next: (end < self.rows.len())
                .then(|| self.cursor(end))
                .transpose()?,
        })
    }
}

/// Stateful offline verifier with constant auxiliary memory. An omitted final
/// page never yields an acknowledgement, and a failed page poisons this verifier.
pub struct AuditExportVerifier {
    keys: Arc<AuditKeyRing>,
    manifest: AuditExportManifest,
    next: usize,
    epoch: u64,
    previous: [u8; 32],
    root: [u8; 32],
    failed: bool,
}

impl AuditExportVerifier {
    /// Verify the manifest against the caller's independently selected fleet,
    /// authorized recipient and trusted current UTC Unix time in seconds.
    /// The selected key set is trust input, never taken from export bytes.
    pub fn new(
        keys: Arc<AuditKeyRing>,
        manifest: AuditExportManifest,
        identity: ConfigConsensusIdentity,
        recipient: AuditCaller,
        now: i64,
    ) -> Result<Self, AuditAuthorityError> {
        manifest.verify(&keys, identity, recipient, now)?;
        Ok(Self {
            keys,
            next: 0,
            epoch: manifest.body.floor_epoch,
            previous: manifest.body.floor_anchor,
            root: manifest.body.predecessor,
            manifest,
            failed: false,
        })
    }

    /// Accept exactly the next page. Duplicate/reordered/substituted rows,
    /// altered continuation and mixing exports fail closed.
    pub fn accept(&mut self, page: &AuditExportPage) -> Result<(), AuditAuthorityError> {
        if self.failed {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        self.failed = true;
        if page.manifest != self.manifest.mac
            || page.offset != self.next
            || page.rows.len() > MAX_PAGE_ROWS
            || self
                .next
                .checked_add(page.rows.len())
                .is_none_or(|n| n > self.manifest.body.row_count)
            || (page.rows.is_empty() && self.next != self.manifest.body.row_count)
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        for row in &page.rows {
            let expected = self
                .manifest
                .body
                .floor
                .checked_add(self.next as u64 + 1)
                .ok_or(AuditAuthorityError::BindingMismatch)?;
            if row.entry.sequence != expected || row.entry.previous != self.root {
                return Err(AuditAuthorityError::BindingMismatch);
            }
            self.epoch = verify_row(
                &self.keys,
                self.manifest.body.identity,
                self.epoch,
                self.previous,
                &row.entry,
                &row.proof,
            )?;
            self.previous = row.proof.signature;
            self.root = row.entry.mac;
            self.next += 1;
        }
        match (&page.next, self.next < self.manifest.body.row_count) {
            (Some(cursor), true)
                if cursor.body.manifest == self.manifest.mac && cursor.body.offset == self.next =>
            {
                verify(
                    self.keys.key(self.manifest.body.active_epoch)?,
                    CURSOR_DOMAIN,
                    &cursor.body,
                    &cursor.mac,
                )?;
            }
            (None, false) => {}
            _ => return Err(AuditAuthorityError::BindingMismatch),
        }
        self.failed = false;
        Ok(())
    }

    /// Produce the non-forgeable SDK acknowledgement only after the exact full
    /// range has verified. This says nothing about recipient authorization,
    /// which remains the consuming application's responsibility.
    pub fn finish(self) -> Result<VerifiedAuditExport, AuditAuthorityError> {
        if self.failed
            || self.next != self.manifest.body.row_count
            || self.root != self.manifest.body.terminal
            || self.previous != self.manifest.body.anchor
            || self.epoch != self.manifest.body.active_epoch
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(VerifiedAuditExport {
            manifest: self.manifest,
        })
    }
}

/// A complete verified export. No public constructor or deserializer can create
/// an acknowledgement from counters or a partial range.
pub struct VerifiedAuditExport {
    pub(crate) manifest: AuditExportManifest,
}
impl std::fmt::Debug for VerifiedAuditExport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedAuditExport(<redacted>)")
    }
}
