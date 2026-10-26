//! SDK-private canonical persistence formats shared by the built-in adapter.
//!
//! These byte containers validate shape only; they are not authority
//! capabilities. An external adapter requires an SDK-issued request-bound
//! codec lease and a real conformance harness before it can qualify under
//! RFC 016 sections 9 and 14.11. Neither surface is published here.
//!
//! Keep the canonical value wrappers and their negative tests beside the
//! shared encoders so withdrawing the incomplete public API preserves format
//! validation coverage.
#![allow(
    dead_code,
    reason = "Private canonical value wrappers retain format coverage; external codec leases are not implemented."
)]

use std::fmt;

use opc_gtpu_ebpf_common::GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN;
use subtle::ConstantTimeEq;

use crate::GtpuSessionSelectorBackendBinding;

/// Canonical namespace-binding codec width.
pub const GTPU_SELECTOR_ADAPTER_BINDING_CODEC_LEN: usize = 145;
/// Canonical operation-stamp codec width.
pub const GTPU_SELECTOR_ADAPTER_STAMP_CODEC_LEN: usize = GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN;
/// Canonical terminal-capsule codec width.
pub const GTPU_SELECTOR_ADAPTER_CAPSULE_CODEC_LEN: usize = 110;

const BINDING_CODEC_VERSION: u8 = 1;
const STAMP_CODEC_VERSION: u8 = 1;
const CAPSULE_CODEC_VERSION: u8 = 1;

/// Stable value-free refusal class for the adapter codecs.
///
/// Deliberately implements neither [`std::fmt::Display`] nor
/// [`std::error::Error`]: every variant is a static class with no source,
/// packet value or identity-bearing context, so there is nothing further to
/// render or chain.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuSelectorAdapterCodecError {
    /// The encoded buffer does not have the exact canonical width.
    InvalidLength,
    /// The version byte is not this codec version.
    UnsupportedVersion,
    /// The versioned value does not satisfy the canonical layout.
    NonCanonical,
}

/// Closed phase class of one canonical operation stamp.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuSelectorAdapterPhase {
    /// A durable install operation is in its pending phase.
    PendingInstall,
    /// A durable remove operation is in its pending phase.
    PendingRemove,
    /// The exact terminal Active stamp.
    TerminalActive,
    /// The exact terminal Retired (absent) stamp.
    TerminalRetired,
}

/// Closed request kind bound by one canonical operation stamp.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuSelectorAdapterRequestKind {
    /// Install an exact selector set.
    Install,
    /// Remove an exact selector set.
    Remove,
}

/// Closed outcome bound by one canonical operation stamp.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuSelectorAdapterOutcome {
    /// The effect is pending durable settlement.
    Pending,
    /// The exact terminal Active readback.
    Active,
    /// The exact terminal absent readback.
    Absent,
}

/// Canonical namespace-binding codec for one external adapter.
///
/// Mint one from the SDK-issued opaque binding, persist the canonical bytes, and
/// later decode and compare them with constant-time equality. There is no raw
/// constructor and the type is not `Clone`; `decode` validates the canonical
/// shape only, not authenticity or attestation, and `Debug` is redacted.
///
/// ```compile_fail
/// use opc_gtpu_dataplane::selector_adapter_codec::GtpuSelectorAdapterBinding;
/// let forged = GtpuSelectorAdapterBinding([0_u8; 145]);
/// ```
///
/// ```compile_fail
/// use opc_gtpu_dataplane::selector_adapter_codec::GtpuSelectorAdapterBinding;
/// fn replay(binding: GtpuSelectorAdapterBinding) {
///     let _copy = binding.clone();
/// }
/// ```
pub struct GtpuSelectorAdapterBinding([u8; GTPU_SELECTOR_ADAPTER_BINDING_CODEC_LEN]);

impl GtpuSelectorAdapterBinding {
    /// Encode the SDK-issued opaque binding into its canonical versioned bytes.
    #[must_use]
    pub fn from_backend_binding(binding: GtpuSessionSelectorBackendBinding) -> Self {
        Self(encode_binding_parts(
            binding.pin_commitment(),
            binding.stable_device().to_bytes(),
            binding.ledger_id(),
            binding.selector_key_commitment(),
            binding.storage_scope_commitment(),
            binding.backend_epoch(),
        ))
    }

    /// Decode one exact canonical namespace binding.
    ///
    /// # Errors
    /// Refuses a non-exact width, an unknown version, or a non-canonical field.
    pub fn decode(bytes: &[u8]) -> Result<Self, GtpuSelectorAdapterCodecError> {
        let value: &[u8; GTPU_SELECTOR_ADAPTER_BINDING_CODEC_LEN] = bytes
            .try_into()
            .map_err(|_| GtpuSelectorAdapterCodecError::InvalidLength)?;
        if value[0] != BINDING_CODEC_VERSION {
            return Err(GtpuSelectorAdapterCodecError::UnsupportedVersion);
        }
        decode_binding_parts(value)
            .map(Self)
            .ok_or(GtpuSelectorAdapterCodecError::NonCanonical)
    }

    /// Exact canonical versioned bytes for durable persistence.
    #[must_use]
    pub fn encode(&self) -> [u8; GTPU_SELECTOR_ADAPTER_BINDING_CODEC_LEN] {
        self.0
    }

    /// Constant-time equality of the complete canonical binding.
    #[must_use]
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl fmt::Debug for GtpuSelectorAdapterBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSelectorAdapterBinding(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding_bytes() -> [u8; GTPU_SELECTOR_ADAPTER_BINDING_CODEC_LEN] {
        encode_binding_parts(
            [0x11; 32], [0x22; 16], [0x33; 16], [0x44; 32], [0x55; 32], [0x66; 16],
        )
    }

    fn stamp(phase: u8, operation: u8, outcome: u8, transaction: [u8; 16]) -> StampParts {
        StampParts {
            phase,
            operation,
            outcome,
            selector_generation: 7,
            nonce: [0x77; 16],
            backend_epoch: [0x66; 16],
            transaction_id: transaction,
            namespace_binding: [0x55; 32],
            group_commitment: [0x88; 32],
            set_commitment: [0x99; 32],
            desired_commitment: [0xaa; 32],
            dataplane_generation: 9,
        }
    }

    fn sample_stamp_bytes() -> [u8; GTPU_SELECTOR_ADAPTER_STAMP_CODEC_LEN] {
        encode_stamp_parts(stamp(1, 1, 1, [0xbb; 16]))
    }

    fn capsule_bytes() -> [u8; GTPU_SELECTOR_ADAPTER_CAPSULE_CODEC_LEN] {
        let mut capsule = [0_u8; GTPU_SELECTOR_ADAPTER_CAPSULE_CODEC_LEN];
        capsule[0] = 1;
        capsule[1..13].copy_from_slice(&[0x01; 12]);
        capsule[13..94].copy_from_slice(&[0x02; 81]);
        capsule[94..].copy_from_slice(&[0x03; 16]);
        capsule
    }

    #[test]
    fn canonical_codec_golden_vectors_preserve_builtin_formats() {
        // RFC 016 frozen v1 binding and stamp fields, using distinct synthetic
        // bytes for every coordinate to catch field reordering or truncation.
        let expected_binding = [
            0x01, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
            0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x55,
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55, 0x55, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66,
        ];
        let expected_stamp = [
            0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x07, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
            0x77, 0x77, 0x77, 0x77, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
            0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x88, 0x88,
            0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
            0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
            0x88, 0x88, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
            0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
            0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(binding_bytes(), expected_binding);
        assert_eq!(sample_stamp_bytes(), expected_stamp);
        assert_eq!(
            GtpuSelectorAdapterBinding::decode(&expected_binding)
                .unwrap()
                .encode(),
            expected_binding
        );
        assert_eq!(
            GtpuSelectorAdapterOperationStamp::decode(&expected_stamp)
                .unwrap()
                .encode(),
            expected_stamp
        );
    }

    #[test]
    fn canonical_binding_round_trips_and_rejects_noncanonical() {
        let bytes = binding_bytes();
        let binding = GtpuSelectorAdapterBinding::decode(&bytes).expect("canonical");
        assert_eq!(binding.encode(), bytes);
        let same = GtpuSelectorAdapterBinding::decode(&bytes).expect("canonical");
        assert!(binding.constant_time_eq(&same));

        assert_eq!(
            GtpuSelectorAdapterBinding::decode(&bytes[..144]).unwrap_err(),
            GtpuSelectorAdapterCodecError::InvalidLength
        );
        let mut wrong = bytes;
        wrong[0] = 2;
        assert_eq!(
            GtpuSelectorAdapterBinding::decode(&wrong).unwrap_err(),
            GtpuSelectorAdapterCodecError::UnsupportedVersion
        );
        for field in [1..33, 33..49, 49..65, 65..97, 97..129, 129..145] {
            let mut zeroed = bytes;
            zeroed[field].fill(0);
            assert_eq!(
                GtpuSelectorAdapterBinding::decode(&zeroed).unwrap_err(),
                GtpuSelectorAdapterCodecError::NonCanonical
            );
        }
        assert_eq!(
            GtpuSelectorAdapterBinding::decode(&[0; 145]).unwrap_err(),
            GtpuSelectorAdapterCodecError::UnsupportedVersion
        );
    }

    #[test]
    fn canonical_stamp_round_trips_every_closed_phase() {
        for (phase, operation, outcome, transaction) in [
            (1_u8, 1_u8, 1_u8, [0xbb; 16]),
            (2, 1, 2, [0; 16]),
            (3, 2, 1, [0xbb; 16]),
            (4, 2, 3, [0; 16]),
        ] {
            let bytes = encode_stamp_parts(stamp(phase, operation, outcome, transaction));
            let decoded = GtpuSelectorAdapterOperationStamp::decode(&bytes).expect("canonical");
            assert_eq!(decoded.encode(), bytes);
            assert_eq!(
                decoded.request_kind(),
                if operation == 1 {
                    GtpuSelectorAdapterRequestKind::Install
                } else {
                    GtpuSelectorAdapterRequestKind::Remove
                }
            );
            assert_eq!(
                decoded.outcome(),
                match outcome {
                    1 => GtpuSelectorAdapterOutcome::Pending,
                    2 => GtpuSelectorAdapterOutcome::Active,
                    _ => GtpuSelectorAdapterOutcome::Absent,
                }
            );
        }
    }

    #[test]
    fn canonical_stamp_rejects_noncanonical_or_inconsistent_values() {
        let bytes = sample_stamp_bytes();
        assert_eq!(
            GtpuSelectorAdapterOperationStamp::decode(&bytes[..207]).unwrap_err(),
            GtpuSelectorAdapterCodecError::InvalidLength
        );
        let mut wrong_version = bytes;
        wrong_version[0] = 2;
        assert_eq!(
            GtpuSelectorAdapterOperationStamp::decode(&wrong_version).unwrap_err(),
            GtpuSelectorAdapterCodecError::UnsupportedVersion
        );
        for offset in [4_usize, 7, 200, 207] {
            let mut wrong = bytes;
            wrong[offset] = 1;
            assert_eq!(
                GtpuSelectorAdapterOperationStamp::decode(&wrong).unwrap_err(),
                GtpuSelectorAdapterCodecError::NonCanonical
            );
        }
        // A canonical value of another codec's width is never reinterpreted.
        for width in [
            GTPU_SELECTOR_ADAPTER_BINDING_CODEC_LEN,
            GTPU_SELECTOR_ADAPTER_CAPSULE_CODEC_LEN,
        ] {
            assert_eq!(
                GtpuSelectorAdapterOperationStamp::decode(&bytes[..width]).unwrap_err(),
                GtpuSelectorAdapterCodecError::InvalidLength
            );
        }
        assert_eq!(
            GtpuSelectorAdapterBinding::decode(&bytes).unwrap_err(),
            GtpuSelectorAdapterCodecError::InvalidLength
        );
        assert_eq!(
            GtpuSelectorAdapterTerminalCapsule::decode(&bytes).unwrap_err(),
            GtpuSelectorAdapterCodecError::InvalidLength
        );
        // A terminal phase must not carry a transaction identity.
        let mut terminal = encode_stamp_parts(stamp(2, 1, 2, [0; 16]));
        terminal[48..64].copy_from_slice(&[0xbb; 16]);
        assert_eq!(
            GtpuSelectorAdapterOperationStamp::decode(&terminal).unwrap_err(),
            GtpuSelectorAdapterCodecError::NonCanonical
        );
        // A pending phase must carry one.
        let mut pending = encode_stamp_parts(stamp(1, 1, 1, [0xbb; 16]));
        pending[48..64].fill(0);
        assert_eq!(
            GtpuSelectorAdapterOperationStamp::decode(&pending).unwrap_err(),
            GtpuSelectorAdapterCodecError::NonCanonical
        );
        // Unknown phase/request/outcome bytes are refused.
        for (offset, value) in [(1_usize, 5_u8), (2, 3), (3, 4)] {
            let mut wrong = bytes;
            wrong[offset] = value;
            assert!(GtpuSelectorAdapterOperationStamp::decode(&wrong).is_err());
        }
        // Mandatory fields must be nonzero.
        for field in [
            8..16,
            16..32,
            32..48,
            64..96,
            96..128,
            128..160,
            160..192,
            192..200,
        ] {
            let mut zeroed = bytes;
            zeroed[field].fill(0);
            assert_eq!(
                GtpuSelectorAdapterOperationStamp::decode(&zeroed).unwrap_err(),
                GtpuSelectorAdapterCodecError::NonCanonical
            );
        }
    }

    #[test]
    fn canonical_stamp_binds_only_its_namespace_and_epoch() {
        let binding = GtpuSelectorAdapterBinding::decode(&binding_bytes()).unwrap();
        let stamp = GtpuSelectorAdapterOperationStamp::decode(&sample_stamp_bytes()).unwrap();
        assert!(stamp.binds(&binding));
        // A different namespace binding commitment or durable epoch fails the
        // constant-time bind without exposing either value.
        for (field, byte) in [(97_usize, 0xee_u8), (129, 0xee)] {
            let mut bytes = binding_bytes();
            bytes[field] = byte;
            let other = GtpuSelectorAdapterBinding::decode(&bytes).unwrap();
            let other_stamp =
                GtpuSelectorAdapterOperationStamp::decode(&sample_stamp_bytes()).unwrap();
            assert!(!other_stamp.binds(&other));
        }
    }

    #[test]
    fn canonical_capsule_round_trips_and_rejects_noncanonical() {
        let bytes = capsule_bytes();
        let capsule = GtpuSelectorAdapterTerminalCapsule::decode(&bytes).expect("canonical");
        assert_eq!(capsule.encode(), bytes);
        let same = GtpuSelectorAdapterTerminalCapsule::decode(&bytes).expect("canonical");
        assert!(capsule.constant_time_eq(&same));
        assert_eq!(
            GtpuSelectorAdapterTerminalCapsule::decode(&bytes[..109]).unwrap_err(),
            GtpuSelectorAdapterCodecError::InvalidLength
        );
        let mut wrong = bytes;
        wrong[0] = 2;
        assert_eq!(
            GtpuSelectorAdapterTerminalCapsule::decode(&wrong).unwrap_err(),
            GtpuSelectorAdapterCodecError::UnsupportedVersion
        );
        assert_eq!(
            GtpuSelectorAdapterTerminalCapsule::decode(&[0; 110]).unwrap_err(),
            GtpuSelectorAdapterCodecError::UnsupportedVersion
        );
        let mut zero_payload = bytes;
        zero_payload[1..].fill(0);
        assert_eq!(
            GtpuSelectorAdapterTerminalCapsule::decode(&zero_payload).unwrap_err(),
            GtpuSelectorAdapterCodecError::NonCanonical
        );
    }

    #[test]
    fn codec_debug_output_redacts_all_values() {
        let binding = GtpuSelectorAdapterBinding::decode(&binding_bytes()).unwrap();
        let stamp = GtpuSelectorAdapterOperationStamp::decode(&sample_stamp_bytes()).unwrap();
        let capsule = GtpuSelectorAdapterTerminalCapsule::decode(&capsule_bytes()).unwrap();
        for debug in [
            format!("{binding:?}"),
            format!("{stamp:?}"),
            format!("{capsule:?}"),
        ] {
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("11"));
            assert!(!debug.contains("55"));
            assert!(!debug.contains("bb"));
        }
    }
}

/// Canonical operation-stamp codec for one external adapter.
///
/// Decode it from durable bytes (or compare two decoded values with
/// constant-time equality) and expose only the closed phase/request/outcome
/// classes. There is no raw field constructor and the type is not `Clone`;
/// `decode` validates the canonical shape only, not authenticity or
/// attestation. There are no named generation, nonce or commitment getters
/// beyond the full persisted blob returned by `encode()`.
pub struct GtpuSelectorAdapterOperationStamp([u8; GTPU_SELECTOR_ADAPTER_STAMP_CODEC_LEN]);

impl GtpuSelectorAdapterOperationStamp {
    /// Decode one exact canonical operation stamp.
    ///
    /// # Errors
    /// Refuses a non-exact width, an unknown version, a non-canonical reserved
    /// region, zero mandatory fields, or an inconsistent phase/outcome tuple.
    pub fn decode(bytes: &[u8]) -> Result<Self, GtpuSelectorAdapterCodecError> {
        let value: &[u8; GTPU_SELECTOR_ADAPTER_STAMP_CODEC_LEN] = bytes
            .try_into()
            .map_err(|_| GtpuSelectorAdapterCodecError::InvalidLength)?;
        if value[0] != STAMP_CODEC_VERSION {
            return Err(GtpuSelectorAdapterCodecError::UnsupportedVersion);
        }
        decode_stamp_parts(value)
            .map(|_| Self(*value))
            .ok_or(GtpuSelectorAdapterCodecError::NonCanonical)
    }

    /// Exact canonical versioned bytes for durable persistence.
    #[must_use]
    pub fn encode(&self) -> [u8; GTPU_SELECTOR_ADAPTER_STAMP_CODEC_LEN] {
        self.0
    }

    /// Constant-time equality of the complete canonical stamp.
    #[must_use]
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }

    /// Closed phase class of this stamp.
    #[must_use]
    pub fn phase(&self) -> GtpuSelectorAdapterPhase {
        match self.0[1] {
            1 => GtpuSelectorAdapterPhase::PendingInstall,
            2 => GtpuSelectorAdapterPhase::TerminalActive,
            3 => GtpuSelectorAdapterPhase::PendingRemove,
            _ => GtpuSelectorAdapterPhase::TerminalRetired,
        }
    }

    /// Closed request kind bound by this stamp.
    #[must_use]
    pub fn request_kind(&self) -> GtpuSelectorAdapterRequestKind {
        if self.0[2] == 2 {
            GtpuSelectorAdapterRequestKind::Remove
        } else {
            GtpuSelectorAdapterRequestKind::Install
        }
    }

    /// Closed outcome bound by this stamp.
    #[must_use]
    pub fn outcome(&self) -> GtpuSelectorAdapterOutcome {
        match self.0[3] {
            1 => GtpuSelectorAdapterOutcome::Pending,
            2 => GtpuSelectorAdapterOutcome::Active,
            _ => GtpuSelectorAdapterOutcome::Absent,
        }
    }

    /// Constant-time check that this stamp's namespace binding and durable
    /// backend epoch belong to `binding`.
    #[must_use]
    pub fn binds(&self, binding: &GtpuSelectorAdapterBinding) -> bool {
        let epoch = &self.0[32..48];
        let namespace = &self.0[64..96];
        let expected_epoch = &binding.0[129..145];
        let expected_namespace = &binding.0[97..129];
        bool::from(epoch.ct_eq(expected_epoch) & namespace.ct_eq(expected_namespace))
    }
}

impl fmt::Debug for GtpuSelectorAdapterOperationStamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSelectorAdapterOperationStamp(<redacted>)")
    }
}

/// Canonical, opaque terminal capsule for one external adapter.
///
/// Only the exact append-only shape is exposed; the authenticated coordinate
/// remains opaque and is never decoded or re-minted here. `decode` validates the
/// canonical shape only, not authenticity or attestation.
pub struct GtpuSelectorAdapterTerminalCapsule([u8; GTPU_SELECTOR_ADAPTER_CAPSULE_CODEC_LEN]);

impl GtpuSelectorAdapterTerminalCapsule {
    /// Decode one canonical terminal capsule shape.
    ///
    /// # Errors
    /// Refuses a non-exact width, an unknown version or an all-zero capsule.
    pub fn decode(bytes: &[u8]) -> Result<Self, GtpuSelectorAdapterCodecError> {
        let value: &[u8; GTPU_SELECTOR_ADAPTER_CAPSULE_CODEC_LEN] = bytes
            .try_into()
            .map_err(|_| GtpuSelectorAdapterCodecError::InvalidLength)?;
        if value[0] != CAPSULE_CODEC_VERSION {
            return Err(GtpuSelectorAdapterCodecError::UnsupportedVersion);
        }
        if value[1..].iter().all(|byte| *byte == 0) {
            return Err(GtpuSelectorAdapterCodecError::NonCanonical);
        }
        Ok(Self(*value))
    }

    /// Exact canonical versioned bytes for durable persistence.
    #[must_use]
    pub fn encode(&self) -> [u8; GTPU_SELECTOR_ADAPTER_CAPSULE_CODEC_LEN] {
        self.0
    }

    /// Constant-time equality of the complete canonical capsule.
    #[must_use]
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl fmt::Debug for GtpuSelectorAdapterTerminalCapsule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSelectorAdapterTerminalCapsule(<redacted>)")
    }
}

/// Canonical namespace-binding bytes shared by the built-in adapter and this
/// private value wrappers, so the formats cannot drift.
pub(crate) fn encode_binding_parts(
    pin_commitment: [u8; 32],
    stable_device: [u8; 16],
    ledger_id: [u8; 16],
    selector_key_commitment: [u8; 32],
    storage_scope_commitment: [u8; 32],
    backend_epoch: [u8; 16],
) -> [u8; GTPU_SELECTOR_ADAPTER_BINDING_CODEC_LEN] {
    let mut codec = [0_u8; GTPU_SELECTOR_ADAPTER_BINDING_CODEC_LEN];
    codec[0] = BINDING_CODEC_VERSION;
    codec[1..33].copy_from_slice(&pin_commitment);
    codec[33..49].copy_from_slice(&stable_device);
    codec[49..65].copy_from_slice(&ledger_id);
    codec[65..97].copy_from_slice(&selector_key_commitment);
    codec[97..129].copy_from_slice(&storage_scope_commitment);
    codec[129..145].copy_from_slice(&backend_epoch);
    codec
}

pub(crate) fn decode_binding_parts(
    value: &[u8; GTPU_SELECTOR_ADAPTER_BINDING_CODEC_LEN],
) -> Option<[u8; GTPU_SELECTOR_ADAPTER_BINDING_CODEC_LEN]> {
    if value[0] != BINDING_CODEC_VERSION
        || value[1..33] == [0; 32]
        || value[33..49] == [0; 16]
        || value[49..65] == [0; 16]
        || value[65..97] == [0; 32]
        || value[97..129] == [0; 32]
        || value[129..145] == [0; 16]
    {
        return None;
    }
    Some(*value)
}

/// Canonical operation-stamp parts shared with the built-in adapter codec.
#[derive(Clone, Copy)]
pub(crate) struct StampParts {
    pub(crate) phase: u8,
    pub(crate) operation: u8,
    pub(crate) outcome: u8,
    pub(crate) selector_generation: u64,
    pub(crate) nonce: [u8; 16],
    pub(crate) backend_epoch: [u8; 16],
    pub(crate) transaction_id: [u8; 16],
    pub(crate) namespace_binding: [u8; 32],
    pub(crate) group_commitment: [u8; 32],
    pub(crate) set_commitment: [u8; 32],
    pub(crate) desired_commitment: [u8; 32],
    pub(crate) dataplane_generation: u64,
}

pub(crate) fn encode_stamp_parts(parts: StampParts) -> [u8; GTPU_SELECTOR_ADAPTER_STAMP_CODEC_LEN] {
    let mut output = [0_u8; GTPU_SELECTOR_ADAPTER_STAMP_CODEC_LEN];
    output[0] = STAMP_CODEC_VERSION;
    output[1] = parts.phase;
    output[2] = parts.operation;
    output[3] = parts.outcome;
    output[8..16].copy_from_slice(&parts.selector_generation.to_be_bytes());
    output[16..32].copy_from_slice(&parts.nonce);
    output[32..48].copy_from_slice(&parts.backend_epoch);
    output[48..64].copy_from_slice(&parts.transaction_id);
    output[64..96].copy_from_slice(&parts.namespace_binding);
    output[96..128].copy_from_slice(&parts.group_commitment);
    output[128..160].copy_from_slice(&parts.set_commitment);
    output[160..192].copy_from_slice(&parts.desired_commitment);
    output[192..200].copy_from_slice(&parts.dataplane_generation.to_be_bytes());
    output
}

pub(crate) fn decode_stamp_parts(
    value: &[u8; GTPU_SELECTOR_ADAPTER_STAMP_CODEC_LEN],
) -> Option<StampParts> {
    if value[0] != STAMP_CODEC_VERSION || value[4..8] != [0; 4] || value[200..208] != [0; 8] {
        return None;
    }
    if !matches!(value[1], 1..=4) || !matches!(value[2], 1..=2) || !matches!(value[3], 1..=3) {
        return None;
    }
    let selector_generation = u64::from_be_bytes(value[8..16].try_into().ok()?);
    let dataplane_generation = u64::from_be_bytes(value[192..200].try_into().ok()?);
    let nonce = value[16..32].try_into().ok()?;
    let backend_epoch = value[32..48].try_into().ok()?;
    let transaction_id = value[48..64].try_into().ok()?;
    let namespace_binding = value[64..96].try_into().ok()?;
    let group_commitment = value[96..128].try_into().ok()?;
    let set_commitment = value[128..160].try_into().ok()?;
    let desired_commitment = value[160..192].try_into().ok()?;
    if selector_generation == 0
        || dataplane_generation == 0
        || nonce == [0; 16]
        || backend_epoch == [0; 16]
        || namespace_binding == [0; 32]
        || group_commitment == [0; 32]
        || set_commitment == [0; 32]
        || desired_commitment == [0; 32]
    {
        return None;
    }
    // Only the four canonical lifecycle tuples are valid; the transaction
    // identity is present exactly for the two pending phases.
    if !matches!(
        (value[1], value[2], value[3], transaction_id == [0; 16]),
        (1, 1, 1, false) | (2, 1, 2, true) | (3, 2, 1, false) | (4, 2, 3, true)
    ) {
        return None;
    }
    Some(StampParts {
        phase: value[1],
        operation: value[2],
        outcome: value[3],
        selector_generation,
        nonce,
        backend_epoch,
        transaction_id,
        namespace_binding,
        group_commitment,
        set_commitment,
        desired_commitment,
        dataplane_generation,
    })
}
