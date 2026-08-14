//! RFC 017 canonical selector-namespace authority codecs.

#![allow(
    dead_code,
    reason = "This staged internal RFC 017 codec is wired by the immediately following implementation slice."
)]

use std::num::NonZeroU64;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const BACKEND_FENCE_COORDINATE_V2_LEN: usize = 32;
const NEXT_LOSS_ENTRY_SCHEDULE_V2_LEN: usize = 120;
const BACKEND_FENCE_COORDINATE_DOMAIN_V2: &[u8] =
    b"opc/gtpu-selector/backend-fence-coordinate/v2\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectorNamespaceCodecError {
    InvalidEncoding,
}

impl SelectorNamespaceCodecError {
    const fn invalid() -> Self {
        Self::InvalidEncoding
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackendFencePhaseV2 {
    Stable = 1,
    StampAbiMigrating = 2,
    GroupInstall = 3,
    GroupRemove = 4,
    DrainQualifying = 5,
    LossQualifying = 6,
    LossQualified = 7,
    RestoreEffect = 8,
    RestoreVerified = 9,
    Decommissioning = 10,
    Decommissioned = 11,
}

impl BackendFencePhaseV2 {
    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Stable),
            2 => Some(Self::StampAbiMigrating),
            3 => Some(Self::GroupInstall),
            4 => Some(Self::GroupRemove),
            5 => Some(Self::DrainQualifying),
            6 => Some(Self::LossQualifying),
            7 => Some(Self::LossQualified),
            8 => Some(Self::RestoreEffect),
            9 => Some(Self::RestoreVerified),
            10 => Some(Self::Decommissioning),
            11 => Some(Self::Decommissioned),
            _ => None,
        }
    }

    const fn requires_complete(self) -> bool {
        matches!(
            self,
            Self::Stable | Self::LossQualified | Self::RestoreVerified | Self::Decommissioned
        )
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackendFenceOutcomeV2 {
    Pending = 1,
    Complete = 2,
}

impl BackendFenceOutcomeV2 {
    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Pending),
            2 => Some(Self::Complete),
            _ => None,
        }
    }
}

struct SelectorNamespaceCommitmentV2([u8; 32]);

impl SelectorNamespaceCommitmentV2 {
    fn new(value: [u8; 32]) -> Result<Self, SelectorNamespaceCodecError> {
        if bool::from(value.ct_eq(&[0; 32])) {
            return Err(SelectorNamespaceCodecError::invalid());
        }

        Ok(Self(value))
    }

    fn matches(&self, candidate: &[u8]) -> bool {
        bool::from(self.0.ct_eq(candidate))
    }
}

struct SelectorNamespaceCommitmentKeyV2(Zeroizing<[u8; 32]>);

impl SelectorNamespaceCommitmentKeyV2 {
    fn new(value: [u8; 32]) -> Result<Self, SelectorNamespaceCodecError> {
        if bool::from(value.ct_eq(&[0; 32])) {
            return Err(SelectorNamespaceCodecError::invalid());
        }

        Ok(Self(Zeroizing::new(value)))
    }

    fn commit(
        &self,
        domain: &[u8],
        encoded: &[u8],
    ) -> Result<SelectorNamespaceCommitmentV2, SelectorNamespaceCodecError> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.0.as_ref())
            .map_err(|_| SelectorNamespaceCodecError::invalid())?;
        mac.update(domain);
        mac.update(encoded);
        SelectorNamespaceCommitmentV2::new(mac.finalize().into_bytes().into())
    }
}

struct BackendFenceCoordinateCodecV2 {
    phase: BackendFencePhaseV2,
    outcome: BackendFenceOutcomeV2,
    generation: NonZeroU64,
    nonce: [u8; 16],
}

impl BackendFenceCoordinateCodecV2 {
    fn new(
        phase: BackendFencePhaseV2,
        outcome: BackendFenceOutcomeV2,
        generation: NonZeroU64,
        nonce: [u8; 16],
    ) -> Result<Self, SelectorNamespaceCodecError> {
        if phase.requires_complete() && outcome != BackendFenceOutcomeV2::Complete {
            return Err(SelectorNamespaceCodecError::invalid());
        }
        if bool::from(nonce.ct_eq(&[0; 16])) {
            return Err(SelectorNamespaceCodecError::invalid());
        }

        Ok(Self {
            phase,
            outcome,
            generation,
            nonce,
        })
    }

    fn decode(encoded: &[u8]) -> Result<Self, SelectorNamespaceCodecError> {
        if encoded.len() != BACKEND_FENCE_COORDINATE_V2_LEN
            || encoded[0] != 2
            || encoded[3..8] != [0; 5]
        {
            return Err(SelectorNamespaceCodecError::invalid());
        }

        let phase = BackendFencePhaseV2::from_tag(encoded[1])
            .ok_or_else(SelectorNamespaceCodecError::invalid)?;
        let outcome = BackendFenceOutcomeV2::from_tag(encoded[2])
            .ok_or_else(SelectorNamespaceCodecError::invalid)?;
        let generation = NonZeroU64::new(u64::from_be_bytes(
            encoded[8..16]
                .try_into()
                .map_err(|_| SelectorNamespaceCodecError::invalid())?,
        ))
        .ok_or_else(SelectorNamespaceCodecError::invalid)?;
        let nonce = encoded[16..32]
            .try_into()
            .map_err(|_| SelectorNamespaceCodecError::invalid())?;

        Self::new(phase, outcome, generation, nonce)
    }

    fn encode(&self) -> [u8; BACKEND_FENCE_COORDINATE_V2_LEN] {
        let mut encoded = [0; BACKEND_FENCE_COORDINATE_V2_LEN];
        encoded[0] = 2;
        encoded[1] = self.phase as u8;
        encoded[2] = self.outcome as u8;
        encoded[8..16].copy_from_slice(&self.generation.get().to_be_bytes());
        encoded[16..32].copy_from_slice(&self.nonce);
        encoded
    }

    fn is_stable_complete(&self) -> bool {
        self.phase == BackendFencePhaseV2::Stable && self.outcome == BackendFenceOutcomeV2::Complete
    }

    const fn generation(&self) -> NonZeroU64 {
        self.generation
    }

    fn commitment(
        &self,
        key: &SelectorNamespaceCommitmentKeyV2,
    ) -> Result<SelectorNamespaceCommitmentV2, SelectorNamespaceCodecError> {
        key.commit(BACKEND_FENCE_COORDINATE_DOMAIN_V2, &self.encode())
    }
}

struct NextLossEntryScheduleCodecV2 {
    namespace_binding: [u8; 32],
    expected_stable_coordinate_commitment: [u8; 32],
    quiesce_intent_generation: NonZeroU64,
    quiesce_intent_nonce: [u8; 16],
    quiesce_completion_generation: NonZeroU64,
    quiesce_completion_nonce: [u8; 16],
}

impl NextLossEntryScheduleCodecV2 {
    fn new(
        namespace_binding: &SelectorNamespaceCommitmentV2,
        commitment_key: &SelectorNamespaceCommitmentKeyV2,
        stable_coordinate: &BackendFenceCoordinateCodecV2,
        quiesce_intent_generation: NonZeroU64,
        quiesce_intent_nonce: [u8; 16],
        quiesce_completion_generation: NonZeroU64,
        quiesce_completion_nonce: [u8; 16],
    ) -> Result<Self, SelectorNamespaceCodecError> {
        if !stable_coordinate.is_stable_complete()
            || quiesce_intent_generation <= stable_coordinate.generation()
            || quiesce_completion_generation <= quiesce_intent_generation
            || bool::from(quiesce_intent_nonce.ct_eq(&[0; 16]))
            || bool::from(quiesce_completion_nonce.ct_eq(&[0; 16]))
            || bool::from(quiesce_intent_nonce.ct_eq(&quiesce_completion_nonce))
        {
            return Err(SelectorNamespaceCodecError::invalid());
        }
        let expected_stable_coordinate_commitment = stable_coordinate.commitment(commitment_key)?;

        Ok(Self {
            namespace_binding: namespace_binding.0,
            expected_stable_coordinate_commitment: expected_stable_coordinate_commitment.0,
            quiesce_intent_generation,
            quiesce_intent_nonce,
            quiesce_completion_generation,
            quiesce_completion_nonce,
        })
    }

    fn decode(
        encoded: &[u8],
        namespace_binding: &SelectorNamespaceCommitmentV2,
        commitment_key: &SelectorNamespaceCommitmentKeyV2,
        stable_coordinate: &BackendFenceCoordinateCodecV2,
    ) -> Result<Self, SelectorNamespaceCodecError> {
        let expected_stable_coordinate_commitment = stable_coordinate.commitment(commitment_key)?;
        if encoded.len() != NEXT_LOSS_ENTRY_SCHEDULE_V2_LEN
            || encoded[0] != 2
            || encoded[1..8] != [0; 7]
            || !namespace_binding.matches(&encoded[8..40])
            || !expected_stable_coordinate_commitment.matches(&encoded[40..72])
        {
            return Err(SelectorNamespaceCodecError::invalid());
        }

        let quiesce_intent_generation = NonZeroU64::new(u64::from_be_bytes(
            encoded[72..80]
                .try_into()
                .map_err(|_| SelectorNamespaceCodecError::invalid())?,
        ))
        .ok_or_else(SelectorNamespaceCodecError::invalid)?;
        let quiesce_intent_nonce = encoded[80..96]
            .try_into()
            .map_err(|_| SelectorNamespaceCodecError::invalid())?;
        let quiesce_completion_generation = NonZeroU64::new(u64::from_be_bytes(
            encoded[96..104]
                .try_into()
                .map_err(|_| SelectorNamespaceCodecError::invalid())?,
        ))
        .ok_or_else(SelectorNamespaceCodecError::invalid)?;
        let quiesce_completion_nonce = encoded[104..120]
            .try_into()
            .map_err(|_| SelectorNamespaceCodecError::invalid())?;

        Self::new(
            namespace_binding,
            commitment_key,
            stable_coordinate,
            quiesce_intent_generation,
            quiesce_intent_nonce,
            quiesce_completion_generation,
            quiesce_completion_nonce,
        )
    }

    fn encode(&self) -> [u8; NEXT_LOSS_ENTRY_SCHEDULE_V2_LEN] {
        let mut encoded = [0; NEXT_LOSS_ENTRY_SCHEDULE_V2_LEN];
        encoded[0] = 2;
        encoded[8..40].copy_from_slice(&self.namespace_binding);
        encoded[40..72].copy_from_slice(&self.expected_stable_coordinate_commitment);
        encoded[72..80].copy_from_slice(&self.quiesce_intent_generation.get().to_be_bytes());
        encoded[80..96].copy_from_slice(&self.quiesce_intent_nonce);
        encoded[96..104].copy_from_slice(&self.quiesce_completion_generation.get().to_be_bytes());
        encoded[104..120].copy_from_slice(&self.quiesce_completion_nonce);
        encoded
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use super::{
        BackendFenceCoordinateCodecV2, BackendFenceOutcomeV2, BackendFencePhaseV2,
        NextLossEntryScheduleCodecV2, SelectorNamespaceCommitmentKeyV2,
        SelectorNamespaceCommitmentV2, BACKEND_FENCE_COORDINATE_V2_LEN,
        NEXT_LOSS_ENTRY_SCHEDULE_V2_LEN,
    };

    const NAMESPACE_BINDING: [u8; 32] = [0x11; 32];
    const COMMITMENT_KEY: [u8; 32] = [0xa5; 32];
    const STABLE_COORDINATE_COMMITMENT: [u8; 32] = [
        0xd3, 0xaf, 0xba, 0x7e, 0xb1, 0x1f, 0x06, 0xe7, 0xfc, 0x02, 0x60, 0x53, 0x3f, 0x24, 0x11,
        0xad, 0x08, 0x13, 0x13, 0x86, 0x3e, 0xe2, 0xbd, 0x4b, 0x46, 0x3d, 0x1f, 0x47, 0x32, 0x2c,
        0xd9, 0xad,
    ];

    fn generation(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).expect("test generations are nonzero")
    }

    fn nonce(value: u8) -> [u8; 16] {
        [value; 16]
    }

    fn commitment(value: [u8; 32]) -> SelectorNamespaceCommitmentV2 {
        SelectorNamespaceCommitmentV2::new(value).expect("test commitments are nonzero")
    }

    fn commitment_key() -> SelectorNamespaceCommitmentKeyV2 {
        SelectorNamespaceCommitmentKeyV2::new(COMMITMENT_KEY)
            .expect("the test selector commitment key is nonzero")
    }

    fn stable_coordinate() -> BackendFenceCoordinateCodecV2 {
        BackendFenceCoordinateCodecV2::new(
            BackendFencePhaseV2::Stable,
            BackendFenceOutcomeV2::Complete,
            generation(40),
            nonce(0x44),
        )
        .expect("the test stable coordinate is canonical")
    }

    #[test]
    fn backend_fence_coordinate_v2_is_exact_and_closed() {
        let coordinate = BackendFenceCoordinateCodecV2::new(
            BackendFencePhaseV2::GroupInstall,
            BackendFenceOutcomeV2::Pending,
            generation(7),
            nonce(0x33),
        )
        .expect("the test coordinate is canonical");

        let encoded = coordinate.encode();
        assert_eq!(encoded.len(), BACKEND_FENCE_COORDINATE_V2_LEN);
        assert_eq!(encoded[0], 2);
        assert_eq!(encoded[1], 3);
        assert_eq!(encoded[2], 1);
        assert_eq!(&encoded[3..8], &[0; 5]);
        assert_eq!(&encoded[8..16], &7_u64.to_be_bytes());
        assert_eq!(&encoded[16..32], &nonce(0x33));
        assert_eq!(
            BackendFenceCoordinateCodecV2::decode(&encoded)
                .expect("the canonical coordinate must decode")
                .encode(),
            encoded
        );
    }

    #[test]
    fn backend_fence_coordinate_v2_accepts_only_the_complete_phase_matrix() {
        let legal = [
            (
                BackendFencePhaseV2::Stable,
                BackendFenceOutcomeV2::Complete,
                1,
            ),
            (
                BackendFencePhaseV2::StampAbiMigrating,
                BackendFenceOutcomeV2::Pending,
                2,
            ),
            (
                BackendFencePhaseV2::StampAbiMigrating,
                BackendFenceOutcomeV2::Complete,
                2,
            ),
            (
                BackendFencePhaseV2::GroupInstall,
                BackendFenceOutcomeV2::Pending,
                3,
            ),
            (
                BackendFencePhaseV2::GroupInstall,
                BackendFenceOutcomeV2::Complete,
                3,
            ),
            (
                BackendFencePhaseV2::GroupRemove,
                BackendFenceOutcomeV2::Pending,
                4,
            ),
            (
                BackendFencePhaseV2::GroupRemove,
                BackendFenceOutcomeV2::Complete,
                4,
            ),
            (
                BackendFencePhaseV2::DrainQualifying,
                BackendFenceOutcomeV2::Pending,
                5,
            ),
            (
                BackendFencePhaseV2::DrainQualifying,
                BackendFenceOutcomeV2::Complete,
                5,
            ),
            (
                BackendFencePhaseV2::LossQualifying,
                BackendFenceOutcomeV2::Pending,
                6,
            ),
            (
                BackendFencePhaseV2::LossQualifying,
                BackendFenceOutcomeV2::Complete,
                6,
            ),
            (
                BackendFencePhaseV2::LossQualified,
                BackendFenceOutcomeV2::Complete,
                7,
            ),
            (
                BackendFencePhaseV2::RestoreEffect,
                BackendFenceOutcomeV2::Pending,
                8,
            ),
            (
                BackendFencePhaseV2::RestoreEffect,
                BackendFenceOutcomeV2::Complete,
                8,
            ),
            (
                BackendFencePhaseV2::RestoreVerified,
                BackendFenceOutcomeV2::Complete,
                9,
            ),
            (
                BackendFencePhaseV2::Decommissioning,
                BackendFenceOutcomeV2::Pending,
                10,
            ),
            (
                BackendFencePhaseV2::Decommissioning,
                BackendFenceOutcomeV2::Complete,
                10,
            ),
            (
                BackendFencePhaseV2::Decommissioned,
                BackendFenceOutcomeV2::Complete,
                11,
            ),
        ];

        for (phase, outcome, phase_tag) in legal {
            let encoded =
                BackendFenceCoordinateCodecV2::new(phase, outcome, generation(7), nonce(0x33))
                    .expect("the RFC phase/outcome pair must be legal")
                    .encode();
            assert_eq!(encoded[1], phase_tag);
            assert!(BackendFenceCoordinateCodecV2::decode(&encoded).is_ok());
        }

        for phase in [
            BackendFencePhaseV2::Stable,
            BackendFencePhaseV2::LossQualified,
            BackendFencePhaseV2::RestoreVerified,
            BackendFencePhaseV2::Decommissioned,
        ] {
            assert!(BackendFenceCoordinateCodecV2::new(
                phase,
                BackendFenceOutcomeV2::Pending,
                generation(7),
                nonce(0x33),
            )
            .is_err());
        }
    }

    #[test]
    fn backend_fence_coordinate_v2_rejects_adversarial_mutations() {
        let encoded = BackendFenceCoordinateCodecV2::new(
            BackendFencePhaseV2::Stable,
            BackendFenceOutcomeV2::Complete,
            generation(9),
            nonce(0x44),
        )
        .expect("the test coordinate is canonical")
        .encode();

        for mutation in [
            (0, 1),
            (1, 0),
            (1, 12),
            (1, 0xff),
            (2, 0),
            (2, 0xff),
            (15, 0),
        ] {
            let mut candidate = encoded;
            candidate[mutation.0] = mutation.1;
            assert!(BackendFenceCoordinateCodecV2::decode(&candidate).is_err());
        }

        for reserved_index in 3..8 {
            let mut candidate = encoded;
            candidate[reserved_index] = 1;
            assert!(BackendFenceCoordinateCodecV2::decode(&candidate).is_err());
        }

        let mut illegal_pair = encoded;
        illegal_pair[2] = 1;
        assert!(BackendFenceCoordinateCodecV2::decode(&illegal_pair).is_err());

        let mut zero_generation = encoded;
        zero_generation[8..16].fill(0);
        assert!(BackendFenceCoordinateCodecV2::decode(&zero_generation).is_err());

        let mut zero_nonce = encoded;
        zero_nonce[16..32].fill(0);
        assert!(BackendFenceCoordinateCodecV2::decode(&zero_nonce).is_err());

        let mut extended = encoded.to_vec();
        extended.push(0);
        assert!(BackendFenceCoordinateCodecV2::decode(&extended).is_err());

        for truncated_len in 0..BACKEND_FENCE_COORDINATE_V2_LEN {
            assert!(BackendFenceCoordinateCodecV2::decode(&encoded[..truncated_len]).is_err());
        }

        assert!(BackendFenceCoordinateCodecV2::new(
            BackendFencePhaseV2::GroupInstall,
            BackendFenceOutcomeV2::Pending,
            generation(7),
            [0; 16],
        )
        .is_err());
    }

    #[test]
    fn next_loss_entry_schedule_v2_roundtrip_preserves_future_coordinates() {
        let namespace_binding = commitment(NAMESPACE_BINDING);
        let commitment_key = commitment_key();
        let stable_coordinate = stable_coordinate();
        let expected_stable_coordinate_commitment = stable_coordinate
            .commitment(&commitment_key)
            .expect("the stable coordinate commitment must be computable");
        assert_eq!(
            expected_stable_coordinate_commitment.0,
            STABLE_COORDINATE_COMMITMENT
        );
        let wrong_domain_commitment = commitment_key
            .commit(
                b"opc/gtpu-selector/next-loss-entry-schedule/v2\0",
                &stable_coordinate.encode(),
            )
            .expect("the wrong-domain test commitment must be computable");
        assert_ne!(
            wrong_domain_commitment.0,
            expected_stable_coordinate_commitment.0
        );
        let schedule = NextLossEntryScheduleCodecV2::new(
            &namespace_binding,
            &commitment_key,
            &stable_coordinate,
            generation(41),
            nonce(0x55),
            generation(42),
            nonce(0x66),
        )
        .expect("the test schedule is canonical");

        let encoded = schedule.encode();
        assert_eq!(encoded.len(), NEXT_LOSS_ENTRY_SCHEDULE_V2_LEN);
        assert_eq!(encoded[0], 2);
        assert_eq!(&encoded[1..8], &[0; 7]);
        assert_eq!(&encoded[8..40], &NAMESPACE_BINDING);
        assert_eq!(&encoded[40..72], &expected_stable_coordinate_commitment.0);
        assert_eq!(&encoded[72..80], &41_u64.to_be_bytes());
        assert_eq!(&encoded[80..96], &nonce(0x55));
        assert_eq!(&encoded[96..104], &42_u64.to_be_bytes());
        assert_eq!(&encoded[104..120], &nonce(0x66));
        assert_eq!(
            NextLossEntryScheduleCodecV2::decode(
                &encoded,
                &namespace_binding,
                &commitment_key,
                &stable_coordinate,
            )
            .expect("the persisted schedule must decode after restart")
            .encode(),
            encoded
        );
    }

    #[test]
    fn next_loss_entry_schedule_v2_rejects_stale_or_ambiguous_coordinates() {
        let namespace_binding = commitment(NAMESPACE_BINDING);
        let commitment_key = commitment_key();
        let stable_coordinate = stable_coordinate();
        let encoded = NextLossEntryScheduleCodecV2::new(
            &namespace_binding,
            &commitment_key,
            &stable_coordinate,
            generation(41),
            nonce(0x55),
            generation(42),
            nonce(0x66),
        )
        .expect("the test schedule is canonical")
        .encode();

        for range in [8..40, 40..72, 72..80, 80..96, 96..104, 104..120] {
            let mut candidate = encoded;
            candidate[range].fill(0);
            assert!(NextLossEntryScheduleCodecV2::decode(
                &candidate,
                &namespace_binding,
                &commitment_key,
                &stable_coordinate,
            )
            .is_err());
        }

        for reserved_index in 1..8 {
            let mut candidate = encoded;
            candidate[reserved_index] = 1;
            assert!(NextLossEntryScheduleCodecV2::decode(
                &candidate,
                &namespace_binding,
                &commitment_key,
                &stable_coordinate,
            )
            .is_err());
        }

        let mut wrong_version = encoded;
        wrong_version[0] = 1;
        assert!(NextLossEntryScheduleCodecV2::decode(
            &wrong_version,
            &namespace_binding,
            &commitment_key,
            &stable_coordinate,
        )
        .is_err());

        let foreign_namespace_binding = commitment([0x99; 32]);
        assert!(NextLossEntryScheduleCodecV2::decode(
            &encoded,
            &foreign_namespace_binding,
            &commitment_key,
            &stable_coordinate,
        )
        .is_err());

        let foreign_commitment_key = SelectorNamespaceCommitmentKeyV2::new([0x88; 32])
            .expect("the foreign test key is nonzero");
        assert!(NextLossEntryScheduleCodecV2::decode(
            &encoded,
            &namespace_binding,
            &foreign_commitment_key,
            &stable_coordinate,
        )
        .is_err());

        let mut reversed_generations = encoded;
        reversed_generations[96..104].copy_from_slice(&40_u64.to_be_bytes());
        assert!(NextLossEntryScheduleCodecV2::decode(
            &reversed_generations,
            &namespace_binding,
            &commitment_key,
            &stable_coordinate,
        )
        .is_err());

        let mut equal_generations = encoded;
        equal_generations[96..104].copy_from_slice(&41_u64.to_be_bytes());
        assert!(NextLossEntryScheduleCodecV2::decode(
            &equal_generations,
            &namespace_binding,
            &commitment_key,
            &stable_coordinate,
        )
        .is_err());

        let mut duplicate_nonce = encoded;
        duplicate_nonce[104..120].copy_from_slice(&nonce(0x55));
        assert!(NextLossEntryScheduleCodecV2::decode(
            &duplicate_nonce,
            &namespace_binding,
            &commitment_key,
            &stable_coordinate,
        )
        .is_err());

        let mut extended = encoded.to_vec();
        extended.push(0);
        assert!(NextLossEntryScheduleCodecV2::decode(
            &extended,
            &namespace_binding,
            &commitment_key,
            &stable_coordinate,
        )
        .is_err());

        for truncated_len in 0..NEXT_LOSS_ENTRY_SCHEDULE_V2_LEN {
            assert!(NextLossEntryScheduleCodecV2::decode(
                &encoded[..truncated_len],
                &namespace_binding,
                &commitment_key,
                &stable_coordinate,
            )
            .is_err());
        }

        let stale_coordinate = BackendFenceCoordinateCodecV2::new(
            BackendFencePhaseV2::Stable,
            BackendFenceOutcomeV2::Complete,
            generation(41),
            nonce(0x77),
        )
        .expect("the stale test coordinate is canonical");
        assert!(NextLossEntryScheduleCodecV2::decode(
            &encoded,
            &namespace_binding,
            &commitment_key,
            &stale_coordinate,
        )
        .is_err());

        assert!(SelectorNamespaceCommitmentV2::new([0; 32]).is_err());
        assert!(SelectorNamespaceCommitmentKeyV2::new([0; 32]).is_err());
        let nonstable_coordinate = BackendFenceCoordinateCodecV2::new(
            BackendFencePhaseV2::GroupInstall,
            BackendFenceOutcomeV2::Complete,
            generation(40),
            nonce(0x77),
        )
        .expect("the nonstable test coordinate is structurally canonical");
        assert!(NextLossEntryScheduleCodecV2::new(
            &namespace_binding,
            &commitment_key,
            &nonstable_coordinate,
            generation(41),
            nonce(0x55),
            generation(42),
            nonce(0x66),
        )
        .is_err());
        assert!(NextLossEntryScheduleCodecV2::new(
            &namespace_binding,
            &commitment_key,
            &stable_coordinate,
            generation(40),
            nonce(0x55),
            generation(42),
            nonce(0x66),
        )
        .is_err());
        assert!(NextLossEntryScheduleCodecV2::new(
            &namespace_binding,
            &commitment_key,
            &stable_coordinate,
            generation(41),
            nonce(0x55),
            generation(41),
            nonce(0x66),
        )
        .is_err());
        assert!(NextLossEntryScheduleCodecV2::new(
            &namespace_binding,
            &commitment_key,
            &stable_coordinate,
            generation(41),
            nonce(0x55),
            generation(42),
            [0; 16],
        )
        .is_err());
        assert!(NextLossEntryScheduleCodecV2::new(
            &namespace_binding,
            &commitment_key,
            &stable_coordinate,
            generation(41),
            nonce(0x55),
            generation(42),
            nonce(0x55),
        )
        .is_err());
        assert!(NextLossEntryScheduleCodecV2::new(
            &namespace_binding,
            &commitment_key,
            &stable_coordinate,
            generation(41),
            [0; 16],
            generation(42),
            nonce(0x66),
        )
        .is_err());
    }
}
