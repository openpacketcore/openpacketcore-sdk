//! RFC 017 selector-namespace authority codecs and opaque backend carriers.

use std::num::NonZeroU64;

use hmac::{Hmac, Mac};
use opc_gtpu_ebpf_common::GtpuSessionDownlinkKey;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[allow(
    dead_code,
    reason = "The staged RFC 017 coordinator has not yet wired the durable codec."
)]
const BACKEND_FENCE_COORDINATE_V2_LEN: usize = 32;
#[allow(
    dead_code,
    reason = "The staged RFC 017 coordinator has not yet wired the durable codec."
)]
const NEXT_LOSS_ENTRY_SCHEDULE_V2_LEN: usize = 120;
#[allow(
    dead_code,
    reason = "The staged RFC 017 coordinator has not yet wired the durable codec."
)]
const BACKEND_FENCE_COORDINATE_DOMAIN_V2: &[u8] =
    b"opc/gtpu-selector/backend-fence-coordinate/v2\0";

const SUBSET_DOMAIN_V1: &[u8] = b"opc/gtpu-selector/subset/v1\0";
const SELECTOR_SET_DOMAIN_V1: &[u8] = b"opc/gtpu-selector/set/v1\0";
const PROVENANCE_SOURCE_DOMAIN_V1: &[u8] = b"opc/gtpu-selector/provenance-source/v1\0";
const PROVENANCE_PARTITION_DOMAIN_V1: &[u8] = b"opc/gtpu-selector/provenance-partition/v1\0";
const MAX_PROVENANCE_ATOMS: usize = 256;
const MAX_PROVENANCE_SOURCES: usize = 32;
const MAX_ATOM_BYTES: usize = 13;
const MAX_SUBSET_BYTES: usize = 3 + MAX_PROVENANCE_ATOMS * MAX_ATOM_BYTES;

#[allow(
    dead_code,
    reason = "The staged RFC 017 coordinator has not yet wired the durable codec."
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectorNamespaceCodecError {
    InvalidEncoding,
}

#[allow(
    dead_code,
    reason = "The staged RFC 017 coordinator has not yet wired the durable codec."
)]
impl SelectorNamespaceCodecError {
    const fn invalid() -> Self {
        Self::InvalidEncoding
    }
}

#[allow(
    dead_code,
    reason = "The staged RFC 017 coordinator has not yet wired the durable codec."
)]
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

#[allow(
    dead_code,
    reason = "The staged RFC 017 coordinator has not yet wired the durable codec."
)]
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

#[allow(
    dead_code,
    reason = "The staged RFC 017 coordinator has not yet wired the durable codec."
)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackendFenceOutcomeV2 {
    Pending = 1,
    Complete = 2,
}

#[allow(
    dead_code,
    reason = "The staged RFC 017 coordinator has not yet wired the durable codec."
)]
impl BackendFenceOutcomeV2 {
    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Pending),
            2 => Some(Self::Complete),
            _ => None,
        }
    }
}

#[allow(
    dead_code,
    reason = "The staged RFC 017 coordinator has not yet wired the durable codec."
)]
struct SelectorNamespaceCommitmentV2([u8; 32]);

#[allow(
    dead_code,
    reason = "The staged RFC 017 coordinator has not yet wired the durable codec."
)]
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

#[allow(
    dead_code,
    reason = "The staged RFC 017 coordinator has not yet wired the durable codec."
)]
struct SelectorNamespaceCommitmentKeyV2(Zeroizing<[u8; 32]>);

#[allow(
    dead_code,
    reason = "The staged RFC 017 coordinator has not yet wired the durable codec."
)]
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

#[allow(
    dead_code,
    reason = "The staged RFC 017 coordinator has not yet wired the durable codec."
)]
struct BackendFenceCoordinateCodecV2 {
    phase: BackendFencePhaseV2,
    outcome: BackendFenceOutcomeV2,
    generation: NonZeroU64,
    nonce: [u8; 16],
}

#[allow(
    dead_code,
    reason = "The staged RFC 017 coordinator has not yet wired the durable codec."
)]
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

#[allow(
    dead_code,
    reason = "The staged RFC 017 coordinator has not yet wired the durable codec."
)]
struct NextLossEntryScheduleCodecV2 {
    namespace_binding: [u8; 32],
    expected_stable_coordinate_commitment: [u8; 32],
    quiesce_intent_generation: NonZeroU64,
    quiesce_intent_nonce: [u8; 16],
    quiesce_completion_generation: NonZeroU64,
    quiesce_completion_nonce: [u8; 16],
}

#[allow(
    dead_code,
    reason = "The staged RFC 017 coordinator has not yet wired the durable codec."
)]
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

fn nonzero_commitment(value: &[u8; 32]) -> Result<(), SelectorNamespaceCodecError> {
    if bool::from(value.ct_eq(&[0; 32])) {
        Err(SelectorNamespaceCodecError::invalid())
    } else {
        Ok(())
    }
}

fn canonical_atom_length(encoded: &[u8]) -> Result<usize, SelectorNamespaceCodecError> {
    if encoded.len() < 3 {
        return Err(SelectorNamespaceCodecError::invalid());
    }
    let tag = encoded[0];
    let length = usize::from(u16::from_be_bytes([encoded[1], encoded[2]]));
    if length == 0 || length > 10 || encoded.len() < 3 + length {
        return Err(SelectorNamespaceCodecError::invalid());
    }
    let payload = &encoded[3..3 + length];
    match tag {
        b'T' => {
            if length != 8 {
                return Err(SelectorNamespaceCodecError::invalid());
            }
            let key: [u8; 8] = payload
                .try_into()
                .map_err(|_| SelectorNamespaceCodecError::invalid())?;
            GtpuSessionDownlinkKey::decode(&key)
                .ok_or_else(SelectorNamespaceCodecError::invalid)?;
        }
        b'P' => {
            let valid = if length == 6 {
                payload[0] == 4 && payload[1] == 32 && payload[2..6].iter().any(|byte| *byte != 0)
            } else if length == 10 {
                payload[0] == 6 && payload[1] == 64 && payload[2..10].iter().any(|byte| *byte != 0)
            } else {
                false
            };
            if !valid {
                return Err(SelectorNamespaceCodecError::invalid());
            }
        }
        b'M' => {
            if length != 8 || payload[0..4] == [0; 4] || payload[4..8] != u32::MAX.to_be_bytes() {
                return Err(SelectorNamespaceCodecError::invalid());
            }
        }
        _ => return Err(SelectorNamespaceCodecError::invalid()),
    }
    Ok(3 + length)
}

#[allow(
    dead_code,
    reason = "RFC 017 provenance is staged behind the coordinator."
)]
struct AtomSubsetCodecV1 {
    atoms: Vec<Vec<u8>>,
}

#[allow(
    dead_code,
    reason = "RFC 017 provenance is staged behind the coordinator."
)]
impl AtomSubsetCodecV1 {
    fn new(atoms: Vec<Vec<u8>>) -> Result<Self, SelectorNamespaceCodecError> {
        if atoms.is_empty() || atoms.len() > MAX_PROVENANCE_ATOMS {
            return Err(SelectorNamespaceCodecError::invalid());
        }
        let mut seen = std::collections::BTreeSet::new();
        for atom in &atoms {
            if canonical_atom_length(atom)? != atom.len() {
                return Err(SelectorNamespaceCodecError::invalid());
            }
            if !seen.insert(atom.clone()) {
                return Err(SelectorNamespaceCodecError::invalid());
            }
        }
        let mut atoms = atoms;
        atoms.sort();
        Ok(Self { atoms })
    }

    fn decode(encoded: &[u8]) -> Result<Self, SelectorNamespaceCodecError> {
        if encoded.len() < 3 || encoded[0] != 1 {
            return Err(SelectorNamespaceCodecError::invalid());
        }
        let count = usize::from(u16::from_be_bytes([encoded[1], encoded[2]]));
        if count == 0 || count > MAX_PROVENANCE_ATOMS || encoded.len() > MAX_SUBSET_BYTES {
            return Err(SelectorNamespaceCodecError::invalid());
        }
        let mut cursor = 3_usize;
        let mut atoms = Vec::with_capacity(count);
        let mut previous: Option<Vec<u8>> = None;
        for _ in 0..count {
            if encoded.len().saturating_sub(cursor) < 3 {
                return Err(SelectorNamespaceCodecError::invalid());
            }
            let atom_len = canonical_atom_length(&encoded[cursor..])?;
            let atom = encoded[cursor..cursor + atom_len].to_vec();
            if previous.as_ref().is_some_and(|p| p >= &atom) {
                return Err(SelectorNamespaceCodecError::invalid());
            }
            previous = Some(atom.clone());
            atoms.push(atom);
            cursor += atom_len;
        }
        if cursor != encoded.len() {
            return Err(SelectorNamespaceCodecError::invalid());
        }
        Ok(Self { atoms })
    }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(3 + self.atoms.len() * MAX_ATOM_BYTES);
        encoded.push(1);
        encoded.extend_from_slice(&(self.atoms.len() as u16).to_be_bytes());
        for atom in &self.atoms {
            encoded.extend_from_slice(atom);
        }
        encoded
    }

    fn len(&self) -> usize {
        self.encode().len()
    }

    fn atoms(&self) -> &[Vec<u8>] {
        &self.atoms
    }

    fn commitment(
        &self,
        key: &SelectorNamespaceCommitmentKeyV2,
    ) -> Result<SelectorNamespaceCommitmentV2, SelectorNamespaceCodecError> {
        key.commit(SUBSET_DOMAIN_V1, &self.encode())
    }
}

#[allow(
    dead_code,
    reason = "RFC 017 provenance is staged behind the coordinator."
)]
struct ProvenanceSourceCodecV1 {
    namespace_binding: [u8; 32],
    candidate_group: [u8; 32],
    candidate_set: [u8; 32],
    candidate_desired: [u8; 32],
    kind: ProvenanceSourceKindV1,
    subset: AtomSubsetCodecV1,
}

#[allow(
    dead_code,
    reason = "RFC 017 provenance is staged behind the coordinator."
)]
enum ProvenanceSourceKindV1 {
    NeverPublished,
    RetiredSubset {
        predecessor_group: [u8; 32],
        predecessor_set: [u8; 32],
        terminal_generation: NonZeroU64,
        qualification: [u8; 32],
    },
}

#[allow(
    dead_code,
    reason = "RFC 017 provenance is staged behind the coordinator."
)]
impl ProvenanceSourceCodecV1 {
    fn never_published(
        namespace_binding: [u8; 32],
        candidate_group: [u8; 32],
        candidate_set: [u8; 32],
        candidate_desired: [u8; 32],
        subset: AtomSubsetCodecV1,
    ) -> Result<Self, SelectorNamespaceCodecError> {
        for value in [
            &namespace_binding,
            &candidate_group,
            &candidate_set,
            &candidate_desired,
        ] {
            nonzero_commitment(value)?;
        }
        Ok(Self {
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            kind: ProvenanceSourceKindV1::NeverPublished,
            subset,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn retired_subset(
        namespace_binding: [u8; 32],
        candidate_group: [u8; 32],
        candidate_set: [u8; 32],
        candidate_desired: [u8; 32],
        subset: AtomSubsetCodecV1,
        predecessor_group: [u8; 32],
        predecessor_set: [u8; 32],
        terminal_generation: NonZeroU64,
        qualification: [u8; 32],
    ) -> Result<Self, SelectorNamespaceCodecError> {
        for value in [
            &namespace_binding,
            &candidate_group,
            &candidate_set,
            &candidate_desired,
            &predecessor_group,
            &predecessor_set,
            &qualification,
        ] {
            nonzero_commitment(value)?;
        }
        Ok(Self {
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            kind: ProvenanceSourceKindV1::RetiredSubset {
                predecessor_group,
                predecessor_set,
                terminal_generation,
                qualification,
            },
            subset,
        })
    }

    fn decode(encoded: &[u8]) -> Result<Self, SelectorNamespaceCodecError> {
        if encoded.len() < 134 || encoded[0] != 1 {
            return Err(SelectorNamespaceCodecError::invalid());
        }
        let namespace_binding = encoded[1..33]
            .try_into()
            .map_err(|_| SelectorNamespaceCodecError::invalid())?;
        let candidate_group = encoded[33..65]
            .try_into()
            .map_err(|_| SelectorNamespaceCodecError::invalid())?;
        let candidate_set = encoded[65..97]
            .try_into()
            .map_err(|_| SelectorNamespaceCodecError::invalid())?;
        let candidate_desired = encoded[97..129]
            .try_into()
            .map_err(|_| SelectorNamespaceCodecError::invalid())?;
        for value in [
            &namespace_binding,
            &candidate_group,
            &candidate_set,
            &candidate_desired,
        ] {
            nonzero_commitment(value)?;
        }
        let kind = encoded[129];
        let subset_len = usize::try_from(u32::from_be_bytes(
            encoded[130..134]
                .try_into()
                .map_err(|_| SelectorNamespaceCodecError::invalid())?,
        ))
        .map_err(|_| SelectorNamespaceCodecError::invalid())?;
        if !(3..=MAX_SUBSET_BYTES).contains(&subset_len) || encoded.len() < 134 + subset_len {
            return Err(SelectorNamespaceCodecError::invalid());
        }
        let subset = AtomSubsetCodecV1::decode(&encoded[134..134 + subset_len])?;
        let tail = &encoded[134 + subset_len..];
        match kind {
            1 if tail.is_empty() => Self::never_published(
                namespace_binding,
                candidate_group,
                candidate_set,
                candidate_desired,
                subset,
            ),
            2 if tail.len() == 104 => {
                let predecessor_group = tail[0..32]
                    .try_into()
                    .map_err(|_| SelectorNamespaceCodecError::invalid())?;
                let predecessor_set = tail[32..64]
                    .try_into()
                    .map_err(|_| SelectorNamespaceCodecError::invalid())?;
                let terminal_generation = NonZeroU64::new(u64::from_be_bytes(
                    tail[64..72]
                        .try_into()
                        .map_err(|_| SelectorNamespaceCodecError::invalid())?,
                ))
                .ok_or_else(SelectorNamespaceCodecError::invalid)?;
                let qualification = tail[72..104]
                    .try_into()
                    .map_err(|_| SelectorNamespaceCodecError::invalid())?;
                Self::retired_subset(
                    namespace_binding,
                    candidate_group,
                    candidate_set,
                    candidate_desired,
                    subset,
                    predecessor_group,
                    predecessor_set,
                    terminal_generation,
                    qualification,
                )
            }
            _ => Err(SelectorNamespaceCodecError::invalid()),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(134 + self.subset.len() + 104);
        encoded.push(1);
        encoded.extend_from_slice(&self.namespace_binding);
        encoded.extend_from_slice(&self.candidate_group);
        encoded.extend_from_slice(&self.candidate_set);
        encoded.extend_from_slice(&self.candidate_desired);
        match &self.kind {
            ProvenanceSourceKindV1::NeverPublished => encoded.push(1),
            ProvenanceSourceKindV1::RetiredSubset {
                predecessor_group,
                predecessor_set,
                terminal_generation,
                qualification,
            } => {
                encoded.push(2);
                // Tail is written after the subset length and bytes below.
                let subset = self.subset.encode();
                encoded.extend_from_slice(&(subset.len() as u32).to_be_bytes());
                encoded.extend_from_slice(&subset);
                encoded.extend_from_slice(predecessor_group);
                encoded.extend_from_slice(predecessor_set);
                encoded.extend_from_slice(&terminal_generation.get().to_be_bytes());
                encoded.extend_from_slice(qualification);
                return encoded;
            }
        }
        let subset = self.subset.encode();
        encoded.extend_from_slice(&(subset.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&subset);
        encoded
    }

    fn subset(&self) -> &AtomSubsetCodecV1 {
        &self.subset
    }

    fn commitment(
        &self,
        key: &SelectorNamespaceCommitmentKeyV2,
    ) -> Result<SelectorNamespaceCommitmentV2, SelectorNamespaceCodecError> {
        key.commit(PROVENANCE_SOURCE_DOMAIN_V1, &self.encode())
    }
}

#[allow(
    dead_code,
    reason = "RFC 017 provenance is staged behind the coordinator."
)]
struct ProvenancePartitionCodecV1 {
    namespace_binding: [u8; 32],
    candidate_group: [u8; 32],
    candidate_set: [u8; 32],
    candidate_desired: [u8; 32],
    sources: Vec<ProvenanceSourceCodecV1>,
}

#[allow(
    dead_code,
    reason = "RFC 017 provenance is staged behind the coordinator."
)]
impl ProvenancePartitionCodecV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        namespace_binding: [u8; 32],
        candidate_group: [u8; 32],
        candidate_desired: [u8; 32],
        candidate: &AtomSubsetCodecV1,
        commitment_key: &SelectorNamespaceCommitmentKeyV2,
        mut sources: Vec<ProvenanceSourceCodecV1>,
    ) -> Result<Self, SelectorNamespaceCodecError> {
        for value in [&namespace_binding, &candidate_group, &candidate_desired] {
            nonzero_commitment(value)?;
        }
        let candidate_set = commitment_key
            .commit(SELECTOR_SET_DOMAIN_V1, &candidate.encode())?
            .0;
        if sources.is_empty() || sources.len() > MAX_PROVENANCE_SOURCES {
            return Err(SelectorNamespaceCodecError::invalid());
        }
        Self::validate_sources(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            candidate,
            &sources,
        )?;
        sources.sort_by_key(|source| source.encode());
        Ok(Self {
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            sources,
        })
    }

    fn validate_sources(
        namespace_binding: [u8; 32],
        candidate_group: [u8; 32],
        candidate_set: [u8; 32],
        candidate_desired: [u8; 32],
        candidate: &AtomSubsetCodecV1,
        sources: &[ProvenanceSourceCodecV1],
    ) -> Result<(), SelectorNamespaceCodecError> {
        let candidate_atoms = candidate
            .atoms
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let mut union = std::collections::BTreeSet::new();
        let mut complete_sources = std::collections::BTreeSet::new();
        let mut retired_predecessors = std::collections::BTreeSet::new();
        let mut saw_never_published = false;
        for source in sources {
            if source.namespace_binding != namespace_binding
                || source.candidate_group != candidate_group
                || source.candidate_set != candidate_set
                || source.candidate_desired != candidate_desired
            {
                return Err(SelectorNamespaceCodecError::invalid());
            }
            let encoded = source.encode();
            if !complete_sources.insert(encoded) {
                return Err(SelectorNamespaceCodecError::invalid());
            }
            match &source.kind {
                ProvenanceSourceKindV1::NeverPublished => {
                    if saw_never_published {
                        return Err(SelectorNamespaceCodecError::invalid());
                    }
                    saw_never_published = true;
                }
                ProvenanceSourceKindV1::RetiredSubset {
                    predecessor_group, ..
                } => {
                    if !retired_predecessors.insert(*predecessor_group) {
                        return Err(SelectorNamespaceCodecError::invalid());
                    }
                }
            }
            for atom in source.subset.atoms() {
                if !candidate_atoms.contains(atom) || !union.insert(atom.clone()) {
                    return Err(SelectorNamespaceCodecError::invalid());
                }
            }
        }
        if union != candidate_atoms {
            return Err(SelectorNamespaceCodecError::invalid());
        }
        Ok(())
    }

    fn decode(
        encoded: &[u8],
        candidate: &AtomSubsetCodecV1,
        commitment_key: &SelectorNamespaceCommitmentKeyV2,
    ) -> Result<Self, SelectorNamespaceCodecError> {
        if encoded.len() < 131 || encoded[0] != 1 {
            return Err(SelectorNamespaceCodecError::invalid());
        }
        let namespace_binding = encoded[1..33]
            .try_into()
            .map_err(|_| SelectorNamespaceCodecError::invalid())?;
        let candidate_group = encoded[33..65]
            .try_into()
            .map_err(|_| SelectorNamespaceCodecError::invalid())?;
        let candidate_set = encoded[65..97]
            .try_into()
            .map_err(|_| SelectorNamespaceCodecError::invalid())?;
        let candidate_desired = encoded[97..129]
            .try_into()
            .map_err(|_| SelectorNamespaceCodecError::invalid())?;
        for value in [
            &namespace_binding,
            &candidate_group,
            &candidate_set,
            &candidate_desired,
        ] {
            nonzero_commitment(value)?;
        }
        let expected_candidate_set =
            commitment_key.commit(SELECTOR_SET_DOMAIN_V1, &candidate.encode())?;
        if !expected_candidate_set.matches(&candidate_set) {
            return Err(SelectorNamespaceCodecError::invalid());
        }
        let count = usize::from(u16::from_be_bytes([encoded[129], encoded[130]]));
        if count == 0 || count > MAX_PROVENANCE_SOURCES {
            return Err(SelectorNamespaceCodecError::invalid());
        }
        let mut cursor = 131_usize;
        let mut sources = Vec::with_capacity(count);
        let mut previous: Option<Vec<u8>> = None;
        for _ in 0..count {
            if encoded.len().saturating_sub(cursor) < 4 {
                return Err(SelectorNamespaceCodecError::invalid());
            }
            let source_len = usize::try_from(u32::from_be_bytes(
                encoded[cursor..cursor + 4]
                    .try_into()
                    .map_err(|_| SelectorNamespaceCodecError::invalid())?,
            ))
            .map_err(|_| SelectorNamespaceCodecError::invalid())?;
            cursor += 4;
            if !(134..=134 + MAX_SUBSET_BYTES + 104).contains(&source_len)
                || encoded.len().saturating_sub(cursor) < source_len
            {
                return Err(SelectorNamespaceCodecError::invalid());
            }
            let source_bytes = &encoded[cursor..cursor + source_len];
            if previous
                .as_ref()
                .is_some_and(|p| p.as_slice() >= source_bytes)
            {
                return Err(SelectorNamespaceCodecError::invalid());
            }
            let source = ProvenanceSourceCodecV1::decode(source_bytes)?;
            previous = Some(source_bytes.to_vec());
            sources.push(source);
            cursor += source_len;
        }
        if cursor != encoded.len() {
            return Err(SelectorNamespaceCodecError::invalid());
        }
        Self::validate_sources(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            candidate,
            &sources,
        )?;
        Ok(Self {
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            sources,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.push(1);
        encoded.extend_from_slice(&self.namespace_binding);
        encoded.extend_from_slice(&self.candidate_group);
        encoded.extend_from_slice(&self.candidate_set);
        encoded.extend_from_slice(&self.candidate_desired);
        encoded.extend_from_slice(&(self.sources.len() as u16).to_be_bytes());
        for source in &self.sources {
            let source_bytes = source.encode();
            encoded.extend_from_slice(&(source_bytes.len() as u32).to_be_bytes());
            encoded.extend_from_slice(&source_bytes);
        }
        encoded
    }

    fn commitment(
        &self,
        key: &SelectorNamespaceCommitmentKeyV2,
    ) -> Result<SelectorNamespaceCommitmentV2, SelectorNamespaceCodecError> {
        key.commit(PROVENANCE_PARTITION_DOMAIN_V1, &self.encode())
    }
}

/// Opaque RFC 017 operation class carried by one SDK-minted backend request.
#[allow(
    dead_code,
    reason = "The coordinator minting and receipt-verification slice follows this port definition."
)]
enum SelectorNamespaceBackendOperationV2 {
    RetiredDrainQualification,
    LossInspection,
    NamespaceRestore,
    NamespaceRestoreReadback,
}

/// Exact private coordinator context for one RFC 017 backend operation.
///
/// This is intentionally not a public capability or serialization format. It
/// retains every commitment needed by later coordinator/backend wiring to
/// reject namespace, group, desired graph, operation, generation, nonce, and
/// epoch substitution before any effect.
#[allow(
    dead_code,
    reason = "The coordinator minting and receipt-verification slice follows this port definition."
)]
struct SelectorNamespaceBackendCoordinateV2 {
    namespace_binding_commitment: [u8; 32],
    device_commitment: [u8; 32],
    group_commitment: [u8; 32],
    selector_set_commitment: [u8; 32],
    desired_commitment: [u8; 32],
    namespace_state_commitment: [u8; 32],
    retained_marker_commitment: [u8; 32],
    generation: NonZeroU64,
    nonce: [u8; 16],
    backend_epoch: [u8; 16],
    operation: SelectorNamespaceBackendOperationV2,
}

/// Opaque request to qualify the complete drain of one retired selector source.
///
/// Only the RFC 017 coordinator can mint this request. It deliberately has no
/// public fields, constructors, decoders, verifiers, formatting, cloning, or
/// serialization traits.
#[must_use = "a retired-drain request must be consumed by its backend call"]
pub struct GtpuSessionSelectorRetiredDrainRequest {
    #[allow(
        dead_code,
        reason = "The coordinator receipt-verification slice follows this port definition."
    )]
    coordinate: SelectorNamespaceBackendCoordinateV2,
}

/// Opaque receipt for one qualified retired-selector drain.
///
/// A future coordinator slice is the sole successful receipt builder.
#[must_use = "a retired-drain receipt must be consumed by the coordinator"]
pub struct GtpuSessionSelectorRetiredDrainReceipt {
    #[allow(
        dead_code,
        reason = "The coordinator receipt-verification slice follows this port definition."
    )]
    coordinate: SelectorNamespaceBackendCoordinateV2,
}

/// Opaque request to inspect complete mutable-loss for one selector namespace.
///
/// Only the RFC 017 coordinator can mint this request. It deliberately has no
/// public fields, constructors, decoders, verifiers, formatting, cloning, or
/// serialization traits.
#[must_use = "a loss-inspection request must be consumed by its backend call"]
pub struct GtpuSessionSelectorNamespaceLossInspectionRequest {
    #[allow(
        dead_code,
        reason = "The coordinator receipt-verification slice follows this port definition."
    )]
    coordinate: SelectorNamespaceBackendCoordinateV2,
}

/// Opaque observation of complete mutable selector-namespace loss.
///
/// A future coordinator slice is the sole successful observation builder.
#[must_use = "a loss observation must be consumed by the coordinator"]
pub struct GtpuSessionSelectorNamespaceLossObservation {
    #[allow(
        dead_code,
        reason = "The coordinator receipt-verification slice follows this port definition."
    )]
    coordinate: SelectorNamespaceBackendCoordinateV2,
}

/// Opaque request to restore one complete selector namespace after qualified loss.
///
/// Only the RFC 017 coordinator can mint this request. It deliberately has no
/// public fields, constructors, decoders, verifiers, formatting, cloning, or
/// serialization traits.
#[must_use = "a namespace-restore request must be consumed by its backend call"]
pub struct GtpuSessionSelectorNamespaceRestoreRequest {
    #[allow(
        dead_code,
        reason = "The coordinator receipt-verification slice follows this port definition."
    )]
    coordinate: SelectorNamespaceBackendCoordinateV2,
}

/// Opaque receipt for one completed selector-namespace restore effect.
///
/// A future coordinator slice is the sole successful receipt builder.
#[must_use = "a restore receipt must be consumed by the readback coordinator"]
pub struct GtpuSessionSelectorNamespaceRestoreReceipt {
    #[allow(
        dead_code,
        reason = "The coordinator receipt-verification slice follows this port definition."
    )]
    coordinate: SelectorNamespaceBackendCoordinateV2,
}

/// Opaque request for the exact readback of one completed namespace restore.
///
/// Only the RFC 017 coordinator can mint this request. It deliberately has no
/// public fields, constructors, decoders, verifiers, formatting, cloning, or
/// serialization traits.
#[must_use = "a restore readback request must be consumed by its backend call"]
pub struct GtpuSessionSelectorNamespaceRestoreReadbackRequest {
    #[allow(
        dead_code,
        reason = "The coordinator receipt-verification slice follows this port definition."
    )]
    coordinate: SelectorNamespaceBackendCoordinateV2,
}

/// Opaque exact readback receipt for one selector-namespace restore.
///
/// A future coordinator slice is the sole successful receipt builder.
#[must_use = "a restore readback receipt must be consumed by the coordinator"]
pub struct GtpuSessionSelectorNamespaceRestoreReadbackReceipt {
    #[allow(
        dead_code,
        reason = "The coordinator receipt-verification slice follows this port definition."
    )]
    coordinate: SelectorNamespaceBackendCoordinateV2,
}

#[cfg(test)]
fn test_backend_coordinate(
    operation: SelectorNamespaceBackendOperationV2,
) -> SelectorNamespaceBackendCoordinateV2 {
    SelectorNamespaceBackendCoordinateV2 {
        namespace_binding_commitment: [1; 32],
        device_commitment: [2; 32],
        group_commitment: [3; 32],
        selector_set_commitment: [4; 32],
        desired_commitment: [5; 32],
        namespace_state_commitment: [6; 32],
        retained_marker_commitment: [7; 32],
        generation: NonZeroU64::MIN,
        nonce: [8; 16],
        backend_epoch: [9; 16],
        operation,
    }
}

#[cfg(test)]
impl GtpuSessionSelectorRetiredDrainRequest {
    pub(crate) fn for_test() -> Self {
        Self {
            coordinate: test_backend_coordinate(
                SelectorNamespaceBackendOperationV2::RetiredDrainQualification,
            ),
        }
    }
}

#[cfg(test)]
impl GtpuSessionSelectorNamespaceLossInspectionRequest {
    pub(crate) fn for_test() -> Self {
        Self {
            coordinate: test_backend_coordinate(
                SelectorNamespaceBackendOperationV2::LossInspection,
            ),
        }
    }
}

#[cfg(test)]
impl GtpuSessionSelectorNamespaceRestoreRequest {
    pub(crate) fn for_test() -> Self {
        Self {
            coordinate: test_backend_coordinate(
                SelectorNamespaceBackendOperationV2::NamespaceRestore,
            ),
        }
    }
}

#[cfg(test)]
impl GtpuSessionSelectorNamespaceRestoreReadbackRequest {
    pub(crate) fn for_test() -> Self {
        Self {
            coordinate: test_backend_coordinate(
                SelectorNamespaceBackendOperationV2::NamespaceRestoreReadback,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use super::{
        AtomSubsetCodecV1, BackendFenceCoordinateCodecV2, BackendFenceOutcomeV2,
        BackendFencePhaseV2, NextLossEntryScheduleCodecV2, ProvenancePartitionCodecV1,
        ProvenanceSourceCodecV1, SelectorNamespaceCommitmentKeyV2, SelectorNamespaceCommitmentV2,
        BACKEND_FENCE_COORDINATE_V2_LEN, MAX_ATOM_BYTES, MAX_PROVENANCE_ATOMS,
        NEXT_LOSS_ENTRY_SCHEDULE_V2_LEN, SELECTOR_SET_DOMAIN_V1,
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

    fn selector_set_commitment(
        candidate: &AtomSubsetCodecV1,
        key: &SelectorNamespaceCommitmentKeyV2,
    ) -> [u8; 32] {
        key.commit(SELECTOR_SET_DOMAIN_V1, &candidate.encode())
            .expect("the test selector set commitment must be computable")
            .0
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

    fn commitment_bytes(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn mark_atom(mark: u32) -> Vec<u8> {
        let mut atom = vec![b'M', 0, 8];
        atom.extend_from_slice(&mark.to_be_bytes());
        atom.extend_from_slice(&u32::MAX.to_be_bytes());
        atom
    }

    fn ipv4_paa_atom(address: [u8; 4]) -> Vec<u8> {
        let mut atom = vec![b'P', 0, 6, 4, 32];
        atom.extend_from_slice(&address);
        atom
    }

    fn ipv6_paa_atom(prefix: [u8; 8]) -> Vec<u8> {
        let mut atom = vec![b'P', 0, 10, 6, 64];
        atom.extend_from_slice(&prefix);
        atom
    }

    fn downlink_atom(teid: u32) -> Vec<u8> {
        let mut atom = vec![b'T', 0, 8, 4, 4, 0, 0];
        atom.extend_from_slice(&teid.to_be_bytes());
        atom
    }

    fn encoded_partition(
        namespace_binding: [u8; 32],
        candidate_group: [u8; 32],
        candidate_set: [u8; 32],
        candidate_desired: [u8; 32],
        sources: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.push(1);
        encoded.extend_from_slice(&namespace_binding);
        encoded.extend_from_slice(&candidate_group);
        encoded.extend_from_slice(&candidate_set);
        encoded.extend_from_slice(&candidate_desired);
        encoded.extend_from_slice(
            &u16::try_from(sources.len())
                .expect("the test source count is bounded")
                .to_be_bytes(),
        );
        for source in sources {
            encoded.extend_from_slice(
                &u32::try_from(source.len())
                    .expect("the test source length is bounded")
                    .to_be_bytes(),
            );
            encoded.extend_from_slice(source);
        }
        encoded
    }

    #[test]
    fn atom_subset_codec_v1_golden_is_sorted_unique_and_padding_free() {
        let mark = mark_atom(0x0102_0304);
        let paa = ipv4_paa_atom([10, 23, 0, 9]);
        let subset = AtomSubsetCodecV1::new(vec![paa.clone(), mark.clone()])
            .expect("the test atoms form one canonical subset");

        let mut expected = vec![1, 0, 2];
        expected.extend_from_slice(&mark);
        expected.extend_from_slice(&paa);
        assert_eq!(subset.encode(), expected);
        assert_eq!(
            AtomSubsetCodecV1::decode(&expected)
                .expect("the golden subset must decode")
                .encode(),
            expected
        );

        assert!(AtomSubsetCodecV1::new(vec![mark.clone(), mark]).is_err());
        assert!(AtomSubsetCodecV1::decode(&[1, 0, 0]).is_err());

        let mut unsorted = vec![1, 0, 2];
        unsorted.extend_from_slice(&paa);
        unsorted.extend_from_slice(&mark_atom(0x0102_0304));
        assert!(AtomSubsetCodecV1::decode(&unsorted).is_err());

        let unknown_tag = [1, 0, 1, b'X', 0, 1, 1];
        assert!(AtomSubsetCodecV1::decode(&unknown_tag).is_err());

        let mut trailing = expected;
        trailing.push(0);
        assert!(AtomSubsetCodecV1::decode(&trailing).is_err());

        let mut atom_with_trailing_byte = ipv4_paa_atom([10, 23, 0, 9]);
        atom_with_trailing_byte.push(0);
        assert!(AtomSubsetCodecV1::new(vec![atom_with_trailing_byte]).is_err());

        let ipv6 = ipv6_paa_atom([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]);
        assert_eq!(ipv6.len(), MAX_ATOM_BYTES);
        assert_eq!(
            AtomSubsetCodecV1::decode(
                &AtomSubsetCodecV1::new(vec![ipv6])
                    .expect("the maximum-length RFC 016 atom is canonical")
                    .encode(),
            )
            .expect("the maximum-length RFC 016 atom must decode")
            .atoms()
            .len(),
            1
        );

        let mut noncanonical_teid = downlink_atom(0x1000_0001);
        noncanonical_teid[5] = 1;
        let mut zero_mark = mark_atom(7);
        zero_mark[3..7].fill(0);
        let mut partial_mask = mark_atom(7);
        partial_mask[10] = 0xfe;
        let mut wrong_prefix = ipv4_paa_atom([10, 23, 0, 9]);
        wrong_prefix[4] = 64;
        for atom in [noncanonical_teid, zero_mark, partial_mask, wrong_prefix] {
            assert!(AtomSubsetCodecV1::new(vec![atom]).is_err());
        }

        for zero_paa in [ipv4_paa_atom([0; 4]), ipv6_paa_atom([0; 8])] {
            assert!(AtomSubsetCodecV1::new(vec![zero_paa.clone()]).is_err());
            let mut encoded = vec![1, 0, 1];
            encoded.extend_from_slice(&zero_paa);
            assert!(AtomSubsetCodecV1::decode(&encoded).is_err());
        }

        let maximum = (1..=MAX_PROVENANCE_ATOMS)
            .map(|value| mark_atom(value as u32))
            .collect();
        assert!(AtomSubsetCodecV1::new(maximum).is_ok());
        let one_over = (1..=MAX_PROVENANCE_ATOMS + 1)
            .map(|value| mark_atom(value as u32))
            .collect();
        assert!(AtomSubsetCodecV1::new(one_over).is_err());
    }

    #[test]
    fn provenance_source_codec_v1_golden_covers_never_and_retired_subset() {
        let namespace_binding = commitment_bytes(0x11);
        let candidate_group = commitment_bytes(0x22);
        let candidate_set = commitment_bytes(0x33);
        let candidate_desired = commitment_bytes(0x44);
        let never_subset = AtomSubsetCodecV1::new(vec![downlink_atom(0x1000_0001)])
            .expect("the fresh subset is canonical");
        let retired_subset = AtomSubsetCodecV1::new(vec![ipv4_paa_atom([10, 23, 0, 9])])
            .expect("the retired subset is canonical");

        let never = ProvenanceSourceCodecV1::never_published(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            never_subset,
        )
        .expect("the fresh source is canonical");
        let mut expected_never = vec![1];
        expected_never.extend_from_slice(&namespace_binding);
        expected_never.extend_from_slice(&candidate_group);
        expected_never.extend_from_slice(&candidate_set);
        expected_never.extend_from_slice(&candidate_desired);
        expected_never.push(1);
        let fresh_subset = AtomSubsetCodecV1::new(vec![downlink_atom(0x1000_0001)])
            .expect("the fresh subset remains canonical")
            .encode();
        expected_never.extend_from_slice(
            &u32::try_from(fresh_subset.len())
                .expect("the test subset length is bounded")
                .to_be_bytes(),
        );
        expected_never.extend_from_slice(&fresh_subset);
        assert_eq!(never.encode(), expected_never);

        let retired = ProvenanceSourceCodecV1::retired_subset(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            retired_subset,
            commitment_bytes(0x55),
            commitment_bytes(0x66),
            generation(77),
            commitment_bytes(0x77),
        )
        .expect("the retired source is canonical");
        let retired_encoded = retired.encode();
        assert_eq!(retired_encoded[129], 2);
        assert_eq!(
            &retired_encoded[retired_encoded.len() - 40..retired_encoded.len() - 32],
            &77_u64.to_be_bytes()
        );
        assert_eq!(
            ProvenanceSourceCodecV1::decode(&retired_encoded)
                .expect("the retired source must decode")
                .encode(),
            retired_encoded
        );

        let mut never_with_retired_tail = never.encode();
        never_with_retired_tail.extend_from_slice(&[0xaa; 104]);
        assert!(ProvenanceSourceCodecV1::decode(&never_with_retired_tail).is_err());

        let mut zero_generation = retired_encoded;
        let generation_offset = zero_generation.len() - 40;
        zero_generation[generation_offset..generation_offset + 8].fill(0);
        assert!(ProvenanceSourceCodecV1::decode(&zero_generation).is_err());
    }

    #[test]
    fn provenance_partition_codec_v1_sorts_sources_and_requires_exact_union() {
        let namespace_binding = commitment_bytes(0x11);
        let candidate_group = commitment_bytes(0x22);
        let candidate_desired = commitment_bytes(0x44);
        let mark = mark_atom(7);
        let paa = ipv4_paa_atom([10, 23, 0, 9]);
        let teid = downlink_atom(0x1000_0001);
        let candidate = AtomSubsetCodecV1::new(vec![mark.clone(), paa.clone(), teid.clone()])
            .expect("the candidate set is canonical");
        let key = commitment_key();
        let candidate_set = selector_set_commitment(&candidate, &key);
        let never = ProvenanceSourceCodecV1::never_published(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            AtomSubsetCodecV1::new(vec![teid.clone()]).expect("the fresh subset is canonical"),
        )
        .expect("the fresh source is canonical");
        let retired = ProvenanceSourceCodecV1::retired_subset(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            AtomSubsetCodecV1::new(vec![mark.clone(), paa.clone()])
                .expect("the retired subset is canonical"),
            commitment_bytes(0x55),
            commitment_bytes(0x66),
            generation(77),
            commitment_bytes(0x77),
        )
        .expect("the retired source is canonical");

        let partition = ProvenancePartitionCodecV1::new(
            namespace_binding,
            candidate_group,
            candidate_desired,
            &candidate,
            &key,
            vec![retired, never],
        )
        .expect("the two sources exactly partition the candidate");
        let encoded = partition.encode();
        assert_eq!(
            ProvenancePartitionCodecV1::decode(&encoded, &candidate, &key)
                .expect("the canonical partition must decode")
                .encode(),
            encoded
        );

        let first_source_length = u32::from_be_bytes(
            encoded[131..135]
                .try_into()
                .expect("the source length field is fixed width"),
        ) as usize;
        assert_eq!(encoded[135 + 129], 1, "NeverPublished sorts first");
        let second_length_offset = 135 + first_source_length;
        let second_source_start = second_length_offset + 4;
        assert_eq!(encoded[second_source_start + 129], 2);

        let mut forged_set_commitment = encoded.clone();
        forged_set_commitment[65..97].fill(0xee);
        let source_count = usize::from(u16::from_be_bytes([
            forged_set_commitment[129],
            forged_set_commitment[130],
        ]));
        let mut source_cursor = 131;
        for _ in 0..source_count {
            let source_length = u32::from_be_bytes(
                forged_set_commitment[source_cursor..source_cursor + 4]
                    .try_into()
                    .expect("the source length field is fixed width"),
            ) as usize;
            source_cursor += 4;
            forged_set_commitment[source_cursor + 65..source_cursor + 97].fill(0xee);
            source_cursor += source_length;
        }
        assert!(
            ProvenancePartitionCodecV1::decode(&forged_set_commitment, &candidate, &key)
                .is_err(),
            "a self-consistent caller digest cannot replace the candidate's complete-set commitment"
        );

        let gap = ProvenanceSourceCodecV1::never_published(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            AtomSubsetCodecV1::new(vec![teid.clone()]).expect("the gap source is canonical"),
        )
        .expect("the gap source codec is canonical");
        assert!(ProvenancePartitionCodecV1::new(
            namespace_binding,
            candidate_group,
            candidate_desired,
            &candidate,
            &key,
            vec![gap],
        )
        .is_err());

        let overlap_left = ProvenanceSourceCodecV1::never_published(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            AtomSubsetCodecV1::new(vec![mark.clone(), teid.clone()])
                .expect("the first overlap source is canonical"),
        )
        .expect("the first overlap source codec is canonical");
        let overlap_right = ProvenanceSourceCodecV1::retired_subset(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            AtomSubsetCodecV1::new(vec![mark, paa])
                .expect("the second overlap source is canonical"),
            commitment_bytes(0x55),
            commitment_bytes(0x66),
            generation(77),
            commitment_bytes(0x77),
        )
        .expect("the second overlap source codec is canonical");
        assert!(ProvenancePartitionCodecV1::new(
            namespace_binding,
            candidate_group,
            candidate_desired,
            &candidate,
            &key,
            vec![overlap_left, overlap_right],
        )
        .is_err());
    }

    #[test]
    fn provenance_partition_codec_v1_rejects_noncanonical_order_and_foreign_binding() {
        let namespace_binding = commitment_bytes(0x11);
        let candidate_group = commitment_bytes(0x22);
        let candidate_desired = commitment_bytes(0x44);
        let mark = mark_atom(7);
        let teid = downlink_atom(0x1000_0001);
        let candidate = AtomSubsetCodecV1::new(vec![mark.clone(), teid.clone()])
            .expect("the candidate set is canonical");
        let key = commitment_key();
        let candidate_set = selector_set_commitment(&candidate, &key);
        let never = ProvenanceSourceCodecV1::never_published(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            AtomSubsetCodecV1::new(vec![teid]).expect("the fresh subset is canonical"),
        )
        .expect("the fresh source is canonical");
        let retired = ProvenanceSourceCodecV1::retired_subset(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            AtomSubsetCodecV1::new(vec![mark]).expect("the retired subset is canonical"),
            commitment_bytes(0x55),
            commitment_bytes(0x66),
            generation(77),
            commitment_bytes(0x77),
        )
        .expect("the retired source is canonical");

        let wrong_order = encoded_partition(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            &[retired.encode(), never.encode()],
        );
        assert!(ProvenancePartitionCodecV1::decode(&wrong_order, &candidate, &key).is_err());

        let foreign = ProvenanceSourceCodecV1::never_published(
            commitment_bytes(0x99),
            candidate_group,
            candidate_set,
            candidate_desired,
            AtomSubsetCodecV1::new(vec![downlink_atom(0x1000_0001)])
                .expect("the foreign source subset is canonical"),
        )
        .expect("the foreign source codec is independently canonical");
        let foreign_partition = encoded_partition(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            &[foreign.encode()],
        );
        assert!(ProvenancePartitionCodecV1::decode(&foreign_partition, &candidate, &key).is_err());

        let split_never_left = ProvenanceSourceCodecV1::never_published(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            AtomSubsetCodecV1::new(vec![mark_atom(7)])
                .expect("the first split fresh subset is canonical"),
        )
        .expect("the first split fresh source is independently canonical");
        let split_never_right = ProvenanceSourceCodecV1::never_published(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            AtomSubsetCodecV1::new(vec![downlink_atom(0x1000_0001)])
                .expect("the second split fresh subset is canonical"),
        )
        .expect("the second split fresh source is independently canonical");
        assert!(ProvenancePartitionCodecV1::new(
            namespace_binding,
            candidate_group,
            candidate_desired,
            &candidate,
            &key,
            vec![split_never_left, split_never_right],
        )
        .is_err());

        let repeated_predecessor_left = ProvenanceSourceCodecV1::retired_subset(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            AtomSubsetCodecV1::new(vec![mark_atom(7)])
                .expect("the first repeated-predecessor subset is canonical"),
            commitment_bytes(0x55),
            commitment_bytes(0x66),
            generation(77),
            commitment_bytes(0x77),
        )
        .expect("the first repeated-predecessor source is canonical");
        let repeated_predecessor_right = ProvenanceSourceCodecV1::retired_subset(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            AtomSubsetCodecV1::new(vec![downlink_atom(0x1000_0001)])
                .expect("the second repeated-predecessor subset is canonical"),
            commitment_bytes(0x55),
            commitment_bytes(0x66),
            generation(77),
            commitment_bytes(0x77),
        )
        .expect("the second repeated-predecessor source is canonical");
        assert!(ProvenancePartitionCodecV1::new(
            namespace_binding,
            candidate_group,
            candidate_desired,
            &candidate,
            &key,
            vec![repeated_predecessor_left, repeated_predecessor_right],
        )
        .is_err());
    }

    #[test]
    fn provenance_commitment_domains_match_golden_vectors() {
        let namespace_binding = commitment_bytes(0x11);
        let candidate_group = commitment_bytes(0x22);
        let candidate_desired = commitment_bytes(0x44);
        let key = commitment_key();
        let candidate = AtomSubsetCodecV1::new(vec![downlink_atom(0x1000_0001)])
            .expect("the commitment candidate is canonical");
        let candidate_set = selector_set_commitment(&candidate, &key);
        assert_eq!(
            candidate_set,
            [
                0x49, 0xb1, 0xb8, 0x01, 0x77, 0xdf, 0x46, 0xef, 0x4c, 0xf7, 0xec, 0xaa, 0xc4, 0xcf,
                0x74, 0xc6, 0x43, 0x55, 0x12, 0x8c, 0x4c, 0x34, 0xe6, 0x55, 0x90, 0xe9, 0x45, 0x5a,
                0x52, 0xb7, 0x58, 0x4c,
            ]
        );
        let subset_commitment = candidate
            .commitment(&key)
            .expect("the subset commitment must be computable");
        assert_eq!(
            subset_commitment.0,
            [
                0x60, 0x6a, 0x99, 0x1c, 0xe9, 0x66, 0xa7, 0x32, 0x12, 0xd1, 0x89, 0x97, 0x6c, 0x2f,
                0x4d, 0x67, 0x6c, 0x76, 0x54, 0x67, 0x8e, 0xc2, 0x00, 0x0d, 0x16, 0x8c, 0x84, 0x90,
                0x4a, 0x32, 0x70, 0xfd,
            ]
        );

        let source = ProvenanceSourceCodecV1::never_published(
            namespace_binding,
            candidate_group,
            candidate_set,
            candidate_desired,
            AtomSubsetCodecV1::new(vec![downlink_atom(0x1000_0001)])
                .expect("the commitment source subset is canonical"),
        )
        .expect("the commitment source is canonical");
        let source_commitment = source
            .commitment(&key)
            .expect("the source commitment must be computable");
        assert_eq!(
            source_commitment.0,
            [
                0xcb, 0x88, 0x6b, 0xb5, 0xd2, 0x91, 0xb4, 0xcf, 0xda, 0x9a, 0x22, 0xd3, 0x82, 0x3c,
                0x45, 0xb3, 0xd6, 0xe5, 0x1d, 0x51, 0x3d, 0xfc, 0x63, 0xa9, 0xb2, 0x53, 0xc6, 0xbd,
                0xbb, 0xa2, 0x24, 0xaa,
            ]
        );

        let partition = ProvenancePartitionCodecV1::new(
            namespace_binding,
            candidate_group,
            candidate_desired,
            &candidate,
            &key,
            vec![source],
        )
        .expect("the commitment source exactly covers the candidate");
        let partition_commitment = partition
            .commitment(&key)
            .expect("the partition commitment must be computable");
        assert_eq!(
            partition_commitment.0,
            [
                0x33, 0x69, 0x85, 0xb6, 0x45, 0x67, 0x58, 0xad, 0xf3, 0x5c, 0x08, 0x67, 0xad, 0x4c,
                0x94, 0x07, 0x95, 0x98, 0x26, 0x54, 0x45, 0x70, 0x99, 0x81, 0x56, 0xc0, 0xfb, 0x7d,
                0xcc, 0x9f, 0xf6, 0x10,
            ]
        );
        assert_ne!(subset_commitment.0, source_commitment.0);
        assert_ne!(source_commitment.0, partition_commitment.0);
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
