//! Online recipient verification. Only the authority owns signing material.
//!
//! These bounded messages use the application's authenticated export channel.
//! Decoding a message does not authenticate its sender. In particular a decoded
//! report is neither portable cryptographic proof nor an acknowledgement.

use super::{
    AuditCheckpoint, AuditExportCursor, AuditExportManifest, AuditExportPage, AuditExportSession,
    AuditExportVerifier, AuditKeyRing, VerifiedAuditExport,
};
use crate::audit_authority::{AuditAuthorityError, AuditCaller};
use crate::{ConfigConsensusIdentity, ConsensusConfigStore};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const MAX_MESSAGE_BYTES: usize = 32 * 1024;

macro_rules! message {
    ($ty:ty, $name:literal) => {
        impl $ty {
            /// Encode for the authenticated export channel, never diagnostics.
            pub fn encode(&self) -> Result<Vec<u8>, AuditAuthorityError> {
                let bytes =
                    serde_json::to_vec(self).map_err(|_| AuditAuthorityError::InvalidInput)?;
                if bytes.len() > MAX_MESSAGE_BYTES {
                    return Err(AuditAuthorityError::InvalidInput);
                }
                Ok(bytes)
            }

            /// Decode bounded, untrusted transport data. This authenticates nothing.
            pub fn decode(bytes: &[u8]) -> Result<Self, AuditAuthorityError> {
                if bytes.len() > MAX_MESSAGE_BYTES {
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

/// A fresh recipient request, created by [`AuditRecipientClient`]. The caller
/// claim must match independently authenticated transport input at the authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecipientVerificationRequest {
    version: u16,
    authority: ConfigConsensusIdentity,
    recipient: AuditCaller,
    nonce: [u8; 16],
}
message!(
    AuditRecipientVerificationRequest,
    "AuditRecipientVerificationRequest(<redacted>)"
);

impl AuditRecipientVerificationRequest {
    pub(crate) fn check(
        &self,
        authority: ConfigConsensusIdentity,
        recipient: AuditCaller,
    ) -> Result<(), AuditAuthorityError> {
        if self.version != 1
            || self.authority != authority
            || self.recipient != recipient
            || self.nonce == [0; 16]
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(())
    }
}

/// Exact request, immutable manifest and independently checked freeze witness.
/// Carry this binding on every session call; it does not authorize that call.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecipientSessionBinding {
    request: AuditRecipientVerificationRequest,
    manifest: AuditExportManifest,
    checkpoint_at_freeze: AuditCheckpoint,
}
message!(
    AuditRecipientSessionBinding,
    "AuditRecipientSessionBinding(<redacted>)"
);

impl AuditRecipientSessionBinding {
    /// The exact frozen range, without any signing key material.
    pub fn manifest(&self) -> &AuditExportManifest {
        &self.manifest
    }

    fn live(&self, now: i64) -> Result<(), AuditAuthorityError> {
        let body = &self.manifest.body;
        if now < body.issued_at || now >= body.expires_at {
            return Err(AuditAuthorityError::Expired);
        }
        Ok(())
    }
}

/// Online observation from the authenticated authority. Deserialization is not
/// verification; use the original client's `accept_report` on that same channel.
/// This type cannot be converted to [`VerifiedAuditExport`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecipientVerificationReport {
    binding: AuditRecipientSessionBinding,
    checkpoint_at_finish: AuditCheckpoint,
}
message!(
    AuditRecipientVerificationReport,
    "AuditRecipientVerificationReport(<redacted>)"
);

impl AuditRecipientVerificationReport {
    /// Authenticated export bounds as observed through the admitted online channel.
    pub fn manifest(&self) -> &AuditExportManifest {
        &self.binding.manifest
    }

    /// Independent checkpoint actually checked against this frozen range.
    /// Only this witness establishes the reported frozen checkpoint coverage.
    pub fn checkpoint_at_freeze(&self) -> &AuditCheckpoint {
        &self.binding.checkpoint_at_freeze
    }

    /// A fresh independent observation checked against the current authority.
    /// A larger sequence does not upgrade the frozen range's protected coverage.
    pub fn checkpoint_at_finish(&self) -> &AuditCheckpoint {
        &self.checkpoint_at_finish
    }

    /// Exclusive lower boundary of the authenticated frozen rows.
    pub fn frozen_floor(&self) -> u64 {
        self.binding.manifest.body.floor
    }

    /// Inclusive upper boundary, which may exceed `checkpoint_at_freeze`.
    pub fn frozen_sequence(&self) -> u64 {
        self.binding.manifest.body.sequence
    }
}

/// Recipient-side protocol state. Contains no keyring, signing interface, store,
/// or acknowledgement capability. The application must authenticate the remote
/// authority independently and deliver replies from that channel only. It must
/// never treat a saved report or an arbitrary peer's response as channel input.
pub struct AuditRecipientClient {
    request: AuditRecipientVerificationRequest,
    binding: Option<AuditRecipientSessionBinding>,
    failed: bool,
}

impl AuditRecipientClient {
    /// Start a fresh, non-resumable verification exchange for an independently
    /// selected authority and the application's authenticated recipient scope.
    pub fn new(authority: ConfigConsensusIdentity, recipient: AuditCaller) -> Self {
        Self {
            request: AuditRecipientVerificationRequest {
                version: 1,
                authority,
                recipient,
                nonce: *uuid::Uuid::new_v4().as_bytes(),
            },
            binding: None,
            failed: false,
        }
    }

    /// Bounded request to send on the authenticated export channel.
    pub fn request(&self) -> &AuditRecipientVerificationRequest {
        &self.request
    }

    /// Pin the authority's open response to this fresh request. A bad response
    /// poisons this client. No cryptographic authority is derived from its bytes.
    pub fn accept_opened(&mut self, bytes: &[u8]) -> Result<(), AuditAuthorityError> {
        if self.failed || self.binding.is_some() {
            self.failed = true;
            return Err(AuditAuthorityError::BindingMismatch);
        }
        self.failed = true;
        let binding = AuditRecipientSessionBinding::decode(bytes)?;
        if binding.request != self.request
            || binding.manifest.body.identity != self.request.authority
            || binding.manifest.body.recipient != self.request.recipient
        {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        binding.live(time::OffsetDateTime::now_utc().unix_timestamp())?;
        self.binding = Some(binding);
        self.failed = false;
        Ok(())
    }

    /// Exact opaque binding to echo on all page, received-page and finish calls.
    pub fn binding(&self) -> Result<&AuditRecipientSessionBinding, AuditAuthorityError> {
        if self.failed {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        self.binding
            .as_ref()
            .ok_or(AuditAuthorityError::BindingMismatch)
    }

    /// Accept the final reply from the same authenticated authority, for exactly
    /// this nonce and manifest. This consumes the client to prevent local replay.
    /// It grants no acknowledgement or pruning authority and is not offline proof.
    pub fn accept_report(
        self,
        bytes: &[u8],
    ) -> Result<AuditRecipientVerificationReport, AuditAuthorityError> {
        let binding = self.binding()?;
        let report = AuditRecipientVerificationReport::decode(bytes)?;
        if report.binding != *binding {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        binding.live(time::OffsetDateTime::now_utc().unix_timestamp())?;
        check_checkpoint_progress(&binding.checkpoint_at_freeze, &report.checkpoint_at_finish)?;
        Ok(report)
    }
}

fn check_checkpoint_progress(
    frozen: &AuditCheckpoint,
    current: &AuditCheckpoint,
) -> Result<(), AuditAuthorityError> {
    if current.sequence() < frozen.sequence()
        || (current.sequence() == frozen.sequence() && current != frozen)
    {
        return Err(AuditAuthorityError::RollbackDetected);
    }
    Ok(())
}

/// Authority-owned verifier and frozen export. No serialization, clone, signing
/// accessor or mutable store access is exposed to a recipient. The authenticated
/// transport owner must retain this object and drop it on cancellation/disconnect;
/// expiry refuses further use but does not independently schedule reclamation.
pub struct AuditRecipientExportSession {
    store: ConsensusConfigStore,
    export: AuditExportSession,
    verifier: AuditExportVerifier,
    binding: AuditRecipientSessionBinding,
    failed: bool,
    received_terminal: bool,
}

impl AuditRecipientExportSession {
    pub(crate) fn new(
        store: ConsensusConfigStore,
        export: AuditExportSession,
        keys: Arc<AuditKeyRing>,
        checkpoint_at_freeze: AuditCheckpoint,
        request: AuditRecipientVerificationRequest,
        now: i64,
    ) -> Result<Self, AuditAuthorityError> {
        let manifest = export.manifest().clone();
        let verifier = AuditExportVerifier::new(
            keys,
            manifest.clone(),
            request.authority,
            request.recipient,
            now,
        )?;
        Ok(Self {
            store,
            export,
            verifier,
            binding: AuditRecipientSessionBinding {
                request,
                manifest,
                checkpoint_at_freeze,
            },
            failed: false,
            received_terminal: false,
        })
    }

    /// Open response for the authorized recipient's authenticated channel.
    pub fn binding(&self) -> &AuditRecipientSessionBinding {
        &self.binding
    }

    fn check(
        &self,
        binding: &AuditRecipientSessionBinding,
        recipient: AuditCaller,
    ) -> Result<(), AuditAuthorityError> {
        if self.failed || binding != &self.binding || recipient != self.binding.request.recipient {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        self.binding.live(self.store.recipient_audit_now())
    }

    /// Generate a bounded frozen page. Generating a page never verifies receipt
    /// of that page. `recipient` must come from current transport authentication.
    pub fn page(
        &self,
        binding: &AuditRecipientSessionBinding,
        recipient: AuditCaller,
        cursor: Option<&AuditExportCursor>,
        max_rows: usize,
    ) -> Result<AuditExportPage, AuditAuthorityError> {
        self.check(binding, recipient)?;
        self.export.page_at(
            cursor,
            max_rows,
            recipient,
            self.store.recipient_audit_now(),
        )
    }

    /// Verify the actual page bytes returned by the recipient, using the existing
    /// bounded decoder and streaming verifier. Any failure poisons this session.
    /// Each page, including an empty terminal page, may be accepted only once.
    pub fn accept_received_page(
        &mut self,
        binding: &AuditRecipientSessionBinding,
        recipient: AuditCaller,
        bytes: &[u8],
    ) -> Result<(), AuditAuthorityError> {
        let checked = self.check(binding, recipient);
        self.failed = true;
        checked?;
        if self.received_terminal {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let page = AuditExportPage::decode(bytes)?;
        self.verifier.accept(&page)?;
        self.received_terminal = page.next_cursor().is_none();
        self.failed = false;
        Ok(())
    }

    /// Complete the exact received range and freshly check the independent
    /// checkpoint and current ledger. Cancellation or failure releases this
    /// owner; neither verification nor completion writes any checkpoint/receipt.
    pub async fn finish(
        self,
        binding: &AuditRecipientSessionBinding,
        recipient: AuditCaller,
    ) -> Result<CompletedAuditRecipientVerification, AuditAuthorityError> {
        self.check(binding, recipient)?;
        if !self.received_terminal {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let verified = self.verifier.finish()?;
        let (ledger, checkpoint_at_finish) = self.store.read_recipient_audit_checkpoint().await?;
        // No extension of the original deadline across quorum/provider awaits.
        self.binding.live(self.store.recipient_audit_now())?;
        check_checkpoint_progress(&self.binding.checkpoint_at_freeze, &checkpoint_at_finish)?;
        if ledger.sequence < self.binding.manifest.body.sequence {
            return Err(AuditAuthorityError::RollbackDetected);
        }
        if self.binding.checkpoint_at_freeze.sequence() >= ledger.floor {
            ledger.matches_checkpoint(&self.binding.checkpoint_at_freeze)?;
        }
        if checkpoint_at_finish.sequence() <= self.binding.manifest.body.sequence {
            self.export.matches_checkpoint(&checkpoint_at_finish)?;
        }
        if self.binding.manifest.body.sequence >= ledger.floor {
            ledger.matches_export_manifest(&self.binding.manifest)?;
        }
        Ok(CompletedAuditRecipientVerification {
            report: AuditRecipientVerificationReport {
                binding: self.binding,
                checkpoint_at_finish,
            },
            verified,
            _export: self.export,
        })
    }
}

/// Authority-local completion retaining the export permit and historical keys.
/// Only `report().encode()` crosses the recipient channel. A separate authorized
/// authority action may use `verified_export()` with the existing acknowledgement
/// API; receiving or decoding the report cannot recreate that capability.
pub struct CompletedAuditRecipientVerification {
    report: AuditRecipientVerificationReport,
    verified: VerifiedAuditExport,
    _export: AuditExportSession,
}

impl CompletedAuditRecipientVerification {
    /// Online verification result, without signing material or acknowledgement.
    pub fn report(&self) -> &AuditRecipientVerificationReport {
        &self.report
    }

    /// Genuine authority-local proof for a separately authorized acknowledgement.
    pub fn verified_export(&self) -> &VerifiedAuditExport {
        &self.verified
    }
}

#[cfg(test)]
mod tests;
