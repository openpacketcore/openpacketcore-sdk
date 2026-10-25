//! Authenticated, typed boot refusal over the verified startup session.
//!
//! An issuer may deliver one bounded refusal to the exact worker boot whose
//! candidate proof it verified. The refusal is a hint-free terminal result for
//! that boot attempt: it grants no committed authority, carries no closure
//! evidence, never bypasses an admitted worker's drain/close obligations and is
//! not a substitute for the replayable transient failure classes. It only tells
//! the worker to finish its normal shutdown and start a fresh boot key.
//!
//! The frame reuses the revision-two startup framing and the connection's
//! existing authentication: the configured issuer identity is established by
//! the mutual-TLS policy before the proof, the header is bound to the exact
//! candidate call attempt (`class`, `method`, `installation`, `scope`,
//! `request_id`, `digest`), and the body binds the attempt nonce, the proved
//! boot process nonce and the boot key digest. The body carries only a closed
//! reason code; it never carries credentials, identities, endpoints, evidence
//! or authority.
//!
//! Candidate and liveness handling: a refusal is accepted only on a candidate
//! startup session (`Method::Candidate`). Liveness sessions never receive one,
//! and an already admitted worker has already left the startup session, so its
//! existing closure obligations and RPC authority are untouched.

use super::startup::StartupError;
use super::wire::{FrameKind, Header, Method, WireError, BOOT_REFUSAL_PAYLOAD_BYTES};
use std::fmt;

/// Closed, value-free reason for an authenticated boot refusal.
///
/// The classes mirror the SDK's definitive startup refusal vocabulary: a
/// definitively invalid platform observation, a definitively changed platform
/// observation (for example the workload record catching up with the current
/// container after the proof), or a definitively refused issuer
/// discovery/key-set prerequisite. Transient reads, transport failures,
/// exclusion contention and missing authentication time are never refusal
/// reasons and stay retryable `StartupError::Unavailable`/
/// `StartupError::AuthTimeUnavailable` results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BootRefusalReason {
    /// The installed platform observation is definitively invalid.
    PlatformInvalid,
    /// The platform observation changed and this boot can never reconcile it;
    /// retrying the same boot key cannot succeed.
    PlatformChanged,
    /// The trusted issuer discovery or key-set prerequisite was definitively
    /// refused after activation.
    PrerequisiteRefused,
}

impl BootRefusalReason {
    /// Fixed, value-free label for logs and metrics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlatformInvalid => "platform_invalid",
            Self::PlatformChanged => "platform_changed",
            Self::PrerequisiteRefused => "prerequisite_refused",
        }
    }

    const fn encode(self) -> u8 {
        match self {
            Self::PlatformInvalid => 1,
            Self::PlatformChanged => 2,
            Self::PrerequisiteRefused => 3,
        }
    }

    const fn decode(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::PlatformInvalid),
            2 => Some(Self::PlatformChanged),
            3 => Some(Self::PrerequisiteRefused),
            _ => None,
        }
    }
}

impl fmt::Display for BootRefusalReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Encode one refusal body bound to the exact attempt and proved boot.
pub(super) fn encode_payload(
    attempt_nonce: &[u8; 32],
    process_nonce: &[u8; 16],
    boot_key_digest: &[u8; 32],
    reason: BootRefusalReason,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(BOOT_REFUSAL_PAYLOAD_BYTES);
    body.extend_from_slice(attempt_nonce);
    body.extend_from_slice(process_nonce);
    body.extend_from_slice(boot_key_digest);
    body.push(reason.encode());
    body
}

/// Decode and verify one refusal body against the local attempt and boot.
///
/// A body bound to a different attempt, boot process or boot key is invalid;
/// a replay captured from another boot therefore cannot refuse this boot.
pub(super) fn decode_payload(
    body: &[u8],
    attempt_nonce: &[u8; 32],
    process_nonce: &[u8; 16],
    boot_key_digest: &[u8; 32],
) -> Result<BootRefusalReason, StartupError> {
    if body.len() != BOOT_REFUSAL_PAYLOAD_BYTES {
        return Err(StartupError::Invalid);
    }
    let mut offset = 0;
    let attempt = body.get(offset..offset + 32).ok_or(StartupError::Invalid)?;
    offset += 32;
    let process = body.get(offset..offset + 16).ok_or(StartupError::Invalid)?;
    offset += 16;
    let key = body.get(offset..offset + 32).ok_or(StartupError::Invalid)?;
    offset += 32;
    let reason = body.get(offset).copied().ok_or(StartupError::Invalid)?;
    if attempt != attempt_nonce || process != process_nonce || key != boot_key_digest {
        return Err(StartupError::Invalid);
    }
    BootRefusalReason::decode(reason).ok_or(StartupError::Invalid)
}

/// Encode the complete startup header for one authenticated boot refusal.
///
/// The header is derived from the verified candidate call header, so it keeps
/// the exact protocol installation, scope, request identity and request digest
/// of that attempt and only changes the response frame kind and body length.
pub(super) fn refusal_header(attempt: &Header, body_len: usize) -> Result<Header, StartupError> {
    if attempt.method != Method::Candidate || body_len != BOOT_REFUSAL_PAYLOAD_BYTES {
        return Err(StartupError::Invalid);
    }
    attempt
        .response(FrameKind::BootRefusal, body_len)
        .map_err(|WireError| StartupError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt() -> [u8; 32] {
        [0x11; 32]
    }
    fn process() -> [u8; 16] {
        [0x22; 16]
    }
    fn key() -> [u8; 32] {
        [0x33; 32]
    }

    #[test]
    fn reason_codes_round_trip_and_are_closed() {
        for reason in [
            BootRefusalReason::PlatformInvalid,
            BootRefusalReason::PlatformChanged,
            BootRefusalReason::PrerequisiteRefused,
        ] {
            let body = encode_payload(&attempt(), &process(), &key(), reason);
            assert_eq!(body.len(), BOOT_REFUSAL_PAYLOAD_BYTES);
            assert_eq!(
                decode_payload(&body, &attempt(), &process(), &key()),
                Ok(reason)
            );
            assert!(!reason.as_str().is_empty());
        }
        for code in [0_u8, 4, 0xff] {
            let mut body = encode_payload(
                &attempt(),
                &process(),
                &key(),
                BootRefusalReason::PlatformChanged,
            );
            body[BOOT_REFUSAL_PAYLOAD_BYTES - 1] = code;
            assert_eq!(
                decode_payload(&body, &attempt(), &process(), &key()),
                Err(StartupError::Invalid),
                "an unknown reason code is invalid"
            );
        }
    }

    #[test]
    fn refusals_are_bound_to_the_exact_attempt_and_proved_boot() {
        let body = encode_payload(
            &attempt(),
            &process(),
            &key(),
            BootRefusalReason::PlatformChanged,
        );
        // Replayed to another candidate attempt on the same boot.
        assert_eq!(
            decode_payload(&body, &[0x44; 32], &process(), &key()),
            Err(StartupError::Invalid)
        );
        // Replayed to another boot of the same workload.
        assert_eq!(
            decode_payload(&body, &attempt(), &[0x55; 16], &key()),
            Err(StartupError::Invalid)
        );
        // Replayed to another boot key.
        assert_eq!(
            decode_payload(&body, &attempt(), &process(), &[0x66; 32]),
            Err(StartupError::Invalid)
        );
    }

    #[test]
    fn truncated_or_oversized_refusal_bodies_are_invalid() {
        let body = encode_payload(
            &attempt(),
            &process(),
            &key(),
            BootRefusalReason::PlatformInvalid,
        );
        for length in [0, 1, 80, 82, 96] {
            let mut candidate = body.clone();
            candidate.resize(length, 0);
            assert_eq!(
                decode_payload(&candidate, &attempt(), &process(), &key()),
                Err(StartupError::Invalid)
            );
        }
        // A byte-flipped binding is rejected even at the exact length.
        let mut tampered = body;
        tampered[0] ^= 1;
        assert_eq!(
            decode_payload(&tampered, &attempt(), &process(), &key()),
            Err(StartupError::Invalid)
        );
    }

    fn candidate_header() -> Header {
        Header {
            kind: FrameKind::Call,
            class: super::super::wire::Class::SafetyControl,
            method: Method::Candidate,
            installation: [1; 32],
            scope: [2; 32],
            request_id: [3; 16],
            digest: [4; 32],
            payload_len: 0,
        }
    }

    #[test]
    fn refusal_header_keeps_the_exact_attempt_and_requires_the_candidate_method() {
        let attempt = candidate_header();
        let refusal =
            refusal_header(&attempt, BOOT_REFUSAL_PAYLOAD_BYTES).expect("candidate refusal header");
        assert_eq!(refusal.kind, FrameKind::BootRefusal);
        assert!(refusal.matches_attempt(&attempt));
        // A refusal header captured for one attempt cannot match another.
        let mut other_attempt = candidate_header();
        other_attempt.request_id = [5; 16];
        assert!(!refusal.matches_attempt(&other_attempt));
        // A wrong body length or a non-candidate attempt is refused before any
        // bytes are written.
        assert_eq!(
            refusal_header(&attempt, BOOT_REFUSAL_PAYLOAD_BYTES - 1).err(),
            Some(StartupError::Invalid)
        );
        let mut liveness = candidate_header();
        liveness.method = Method::Liveness;
        assert_eq!(
            refusal_header(&liveness, BOOT_REFUSAL_PAYLOAD_BYTES).err(),
            Some(StartupError::Invalid)
        );
    }
}
