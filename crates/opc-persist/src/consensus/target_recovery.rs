//! Authenticated retained originals, separate from local preparation authority.
//!
//! Old target bytes keep their original serde form. The appended bounded payload
//! uses the existing strict record decoder and both complete command preflights.
//! Neither a deterministic command nor a decoded ledger value owns a local slot.

use std::io::{self, Write};

use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use serde::Deserialize;

use super::{joint_running, PreparedTargetMutation, RecoverySizeCounter, TargetMutationCommand};
use crate::audit_authority::ledger::LedgerMutationError;
use crate::audit_authority::{AuditAuthorityError, AuditCaller, AuditOperationHandle};
use crate::{AuditKey, ConfigConsensusIdentity};

impl TargetMutationCommand {
    pub(in crate::consensus) fn verify_retained(
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

    // Validate the actual retained bytes against a borrowed candidate without
    // decoding another owned copy. The complete verifier runs again; exact
    // canonical equality rejects malformed, noncanonical or substituted input.
    // No result or validation fact survives this call.
    pub(crate) fn verify_canonical_retained(
        &self,
        bytes: &[u8],
        key: &AuditKey,
        identity: ConfigConsensusIdentity,
        original: &AuditOperationHandle,
    ) -> Result<bool, AuditAuthorityError> {
        original.verify(key, identity, original.body.binding.caller)?;
        if bytes.len() > crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
            return Err(AuditAuthorityError::InvalidInput);
        }
        if self.handle() != original || self.bounded_running().is_none() {
            return Ok(false);
        }
        let mut comparison = CanonicalRecovery { remaining: bytes };
        if crate::consensus::config_capacity_json::to_writer(&mut comparison, self).is_err()
            || !comparison.remaining.is_empty()
        {
            // A different submitted command must not invalidate a valid stored
            // original. Preserve the ordinary decoder and receipt classification.
            return Ok(false);
        }
        self.verify_retained(key, identity, original.body.binding.caller)?;
        #[cfg(all(test, target_os = "linux"))]
        crate::consensus::audit_targets::history_gate_tests::apply_original_tests::borrowed_verified(original, bytes.len());
        Ok(true)
    }

    pub(crate) fn encode_retained(
        &self,
        key: &AuditKey,
        identity: ConfigConsensusIdentity,
    ) -> Result<Vec<u8>, LedgerMutationError> {
        self.verify_retained(key, identity, self.handle().body.binding.caller)?;
        let mut size = RecoverySizeCounter(0);
        #[cfg(test)]
        let count_output =
            crate::audit_authority::ledger::native_cost_tests::CountingWriter::new(&mut size);
        #[cfg(not(test))]
        let count_output = &mut size;
        crate::consensus::config_capacity_json::count_to_writer(count_output, self)
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        let mut bytes = RecoveryBytes {
            bytes: Vec::new(),
            remaining: size.0,
        };
        bytes
            .bytes
            .try_reserve_exact(size.0)
            .map_err(|_| LedgerMutationError::Allocation)?;
        // Do not let the serializer grow past the already counted reservation.
        crate::consensus::config_capacity_json::to_writer(&mut bytes, self)
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
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
        #[cfg(test)]
        crate::consensus::storage::config_capacity_apply_observations::observe(
            "target_recovery_entered",
        );
        original.verify(key, identity, caller)?;
        if bytes.len() > crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
            return Err(AuditAuthorityError::InvalidInput);
        }
        // Route without constructing record fields. Trying the legacy parser
        // first could allocate a malformed field preceding the bounded tag.
        let bounded = uses_bounded(bytes).map_err(|_| AuditAuthorityError::InvalidInput)?;
        #[cfg(test)]
        crate::consensus::storage::config_capacity_apply_observations::observe(
            "target_recovery_routed",
        );
        let prepared = if bounded {
            joint_running::decode_unowned(bytes)?
        } else {
            Self::decode(bytes)?
        };
        #[cfg(all(test, target_os = "linux"))]
        crate::consensus::audit_targets::history_gate_tests::apply_original_tests::owned_decoded(
            prepared.handle(),
            bytes.len(),
        );
        #[cfg(test)]
        crate::consensus::storage::config_capacity_apply_observations::observe(
            "target_recovery_decoded",
        );
        if prepared.handle() != original {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        prepared.command.verify_retained(key, identity, caller)?;
        #[cfg(test)]
        crate::consensus::storage::config_capacity_apply_observations::observe(
            "target_recovery_verified",
        );
        let mut comparison = CanonicalRecovery { remaining: bytes };
        crate::consensus::config_capacity_json::to_writer(&mut comparison, &prepared)
            .map_err(|_| AuditAuthorityError::BindingMismatch)?;
        if !comparison.remaining.is_empty() {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        #[cfg(test)]
        crate::consensus::storage::config_capacity_apply_observations::observe(
            "target_recovery_canonical_checked",
        );
        // The caller may inspect an original or validate its outcome, but must
        // acquire its destination reservation before decoding for new work.
        #[cfg(all(test, target_os = "linux"))]
        crate::consensus::audit_targets::history_gate_tests::recovered(original);
        #[cfg(all(test, target_os = "linux"))]
        crate::consensus::audit_targets::history_gate_tests::apply_original_tests::owned_verified(
            original,
            bytes.len(),
        );
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
        #[cfg(test)]
        crate::audit_authority::ledger::native_cost_tests::record(
            crate::audit_authority::ledger::native_cost_tests::Stage::RetainedOutput,
            bytes,
        );
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
        #[cfg(test)]
        crate::audit_authority::ledger::native_cost_tests::record(
            crate::audit_authority::ledger::native_cost_tests::Stage::CanonicalComparison,
            bytes,
        );
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// A separate route entry point lets tests observe bytes consumed by the actual
// slice deserializer. Selection alone never returns an authenticated original.
pub(super) fn uses_bounded(bytes: &[u8]) -> Result<bool, serde_json::Error> {
    let mut input = serde_json::Deserializer::from_slice(bytes);
    let mut bounded = false;
    let _ = RouteProbe {
        at: RouteAt::Root,
        bounded: &mut bounded,
    }
    .deserialize(&mut input);
    #[cfg(test)]
    joint_running::tests::native_route::record_consumed(
        input.into_iter::<IgnoredAny>().byte_offset(),
    );
    if bounded {
        return Ok(true);
    }
    // A negative/inconclusive hint never selects the legacy owned decoder.
    // Preserve the original complete route (including end-of-input) first.
    let mut input = serde_json::Deserializer::from_slice(bytes);
    let result = RecoveryRoute::deserialize(&mut input).and_then(|route| {
        input.end()?;
        Ok(route
            .effect
            .encrypted_payload
            .is_some_and(PayloadRoute::selects_bounded))
    });
    #[cfg(test)]
    joint_running::tests::native_route::record_consumed(
        input.into_iter::<IgnoredAny>().byte_offset(),
    );
    result
}

// Stop at the explicit tag in its structural location, before visiting the
// large byte array. This is an untrusted hint, not a successful parse: the
// unchanged bounded decoder must parse the complete original and reject every
// duplicate, unknown, malformed or trailing field before authentication and
// canonical comparison. No routing result carries a value or local ownership.
#[derive(Clone, Copy)]
enum RouteAt {
    Root,
    Effect,
    Payload,
}

#[derive(Deserialize)]
#[serde(field_identifier)]
enum RouteField {
    #[serde(rename = "effect")]
    Effect,
    #[serde(rename = "encrypted_payload")]
    EncryptedPayload,
    #[serde(rename = "bounded-running")]
    BoundedRunning,
    #[serde(other)]
    Other,
}

struct RouteProbe<'a> {
    at: RouteAt,
    bounded: &'a mut bool,
}

impl<'de> DeserializeSeed<'de> for RouteProbe<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for RouteProbe<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a retained routing object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(field) = map.next_key::<RouteField>()? {
            let next = match (self.at, field) {
                (RouteAt::Root, RouteField::Effect) => RouteAt::Effect,
                (RouteAt::Effect, RouteField::EncryptedPayload) => RouteAt::Payload,
                (RouteAt::Payload, field) => {
                    *self.bounded = matches!(field, RouteField::BoundedRunning);
                    // An intentional error stops Serde without consuming the
                    // payload. Only our local hint is inspected, never error
                    // text supplied by JSON. Non-bounded tags use the full
                    // original route above, including unsupported-tag refusal.
                    return Err(serde::de::Error::custom("retained routing hint complete"));
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                    continue;
                }
            };
            map.next_value_seed(RouteProbe {
                at: next,
                bounded: &mut *self.bounded,
            })?;
        }
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
