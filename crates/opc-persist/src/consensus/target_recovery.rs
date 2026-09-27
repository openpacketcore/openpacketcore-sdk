//! Authenticated retained originals, separate from local preparation authority.
//!
//! Old target bytes keep their original serde form. The appended bounded payload
//! uses the existing strict record decoder and both complete command preflights.
//! Neither a deterministic command nor a decoded ledger value owns a local slot.

use std::io::{self, Write};

use serde::de::IgnoredAny;
use serde::Deserialize;

use super::{joint_running, PreparedTargetMutation, RecoverySizeCounter, TargetMutationCommand};
use crate::audit_authority::ledger::LedgerMutationError;
use crate::audit_authority::{AuditAuthorityError, AuditCaller, AuditOperationHandle};
use crate::{AuditKey, ConfigConsensusIdentity};

impl TargetMutationCommand {
    fn verify_retained(
        &self,
        key: &AuditKey,
        identity: ConfigConsensusIdentity,
        caller: AuditCaller,
    ) -> Result<(), AuditAuthorityError> {
        self.handle().verify(key, identity, caller)?;
        if self.bounded_running().is_some() {
            // This shallow alias is only a size probe, with no local owner.
            // Charge the full Admit and Apply frames before effect serialization.
            let probe = PreparedTargetMutation {
                command: self.clone(),
                preparation: None,
            };
            crate::consensus::store::preflight_joint_target_payload(&probe)?;
            self.verify_bounded_running(key, identity, caller)?;
        } else {
            self.verify_effect(key)?;
        }
        Ok(())
    }

    pub(crate) fn encode_retained(
        &self,
        key: &AuditKey,
        identity: ConfigConsensusIdentity,
    ) -> Result<Vec<u8>, LedgerMutationError> {
        self.verify_retained(key, identity, self.handle().body.binding.caller)?;
        let mut size = RecoverySizeCounter(0);
        serde_json::to_writer(&mut size, self).map_err(|_| AuditAuthorityError::InvalidInput)?;
        let mut bytes = RecoveryBytes {
            bytes: Vec::new(),
            remaining: size.0,
        };
        bytes
            .bytes
            .try_reserve_exact(size.0)
            .map_err(|_| LedgerMutationError::Allocation)?;
        // Do not let the serializer grow past the already counted reservation.
        serde_json::to_writer(&mut bytes, self).map_err(|_| AuditAuthorityError::InvalidInput)?;
        if bytes.bytes.len() != size.0 {
            return Err(AuditAuthorityError::InvalidInput.into());
        }
        Ok(bytes.bytes)
    }
}

impl PreparedTargetMutation {
    pub(crate) fn decode_retained(
        bytes: &[u8],
        key: &AuditKey,
        identity: ConfigConsensusIdentity,
        original: &AuditOperationHandle,
        caller: AuditCaller,
    ) -> Result<Self, AuditAuthorityError> {
        // Independent ledger/caller scope precedes parsing owned payloads.
        original.verify(key, identity, caller)?;
        if bytes.len() > crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
            return Err(AuditAuthorityError::InvalidInput);
        }
        // Route without constructing record fields. Trying the legacy parser
        // first could allocate a malformed field preceding the bounded tag.
        let route: RecoveryRoute =
            serde_json::from_slice(bytes).map_err(|_| AuditAuthorityError::InvalidInput)?;
        let prepared = if route
            .effect
            .encrypted_payload
            .is_some_and(PayloadRoute::selects_bounded)
        {
            joint_running::decode_unowned(bytes)?
        } else {
            Self::decode(bytes)?
        };
        if prepared.handle() != original {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        prepared.command.verify_retained(key, identity, caller)?;
        let mut comparison = CanonicalRecovery { remaining: bytes };
        serde_json::to_writer(&mut comparison, &prepared)
            .map_err(|_| AuditAuthorityError::BindingMismatch)?;
        if !comparison.remaining.is_empty() {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        // The caller may inspect an original or validate its outcome, but must
        // acquire its destination reservation before decoding for new work.
        Ok(prepared)
    }
}

struct RecoveryBytes {
    bytes: Vec<u8>,
    remaining: usize,
}

impl Write for RecoveryBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining
            || bytes.len() > self.bytes.capacity().saturating_sub(self.bytes.len())
        {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        self.bytes.extend_from_slice(bytes);
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct CanonicalRecovery<'a> {
    remaining: &'a [u8],
}

impl Write for CanonicalRecovery<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.remaining.starts_with(bytes) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.remaining = &self.remaining[bytes.len()..];
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Routing only: IgnoredAny skips nested data rather than materializing Values,
// strings or byte collections. The selected complete decoder still rejects
// duplicate/unknown fields. Retained originals must match canonical object
// serialization below; noncanonical sequence forms were already refused.
#[derive(Deserialize)]
struct RecoveryRoute {
    effect: EffectRoute,
}

#[derive(Deserialize)]
struct EffectRoute {
    encrypted_payload: Option<PayloadRoute>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum PayloadRoute {
    Target(IgnoredAny),
    Running(IgnoredAny),
    ProviderCopy(IgnoredAny),
    BoundedRunning(IgnoredAny),
}

impl PayloadRoute {
    fn selects_bounded(self) -> bool {
        match self {
            Self::BoundedRunning(value) => {
                let IgnoredAny = value;
                true
            }
            Self::Target(value) | Self::Running(value) | Self::ProviderCopy(value) => {
                let IgnoredAny = value;
                false
            }
        }
    }
}
