use super::*;
use crate::{
    ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity, ConsensusRequestId,
};
use sha2::{Digest, Sha256};

const FORMAT: &[u8; 4] = b"OPVI";
const VERSION: u16 = 1;
const ATTESTATION_SIGNING_DOMAIN: &[u8] = b"openpacketcore/consensus/lost-voter-attestation/v1\0";
const REPLACEMENT_REQUEST_DOMAIN: &[u8] =
    b"openpacketcore/consensus/replace-lost-voter-request/v1\0";

/// Encode a structurally validated table with exact `OPVI` version 1 framing.
pub fn encode_voter_slot_table(table: &VoterSlotTable) -> Result<Vec<u8>, VoterSlotError> {
    table.validate()?;
    let mut out = Writer(Vec::new());
    out.bytes(FORMAT);
    out.u16(VERSION);
    out.bytes(table.cluster_instance.as_bytes());
    out.bytes(&table.manifest_digest);
    out.u64(table.revision);
    out.u64(table.configuration_epoch.get());
    out.u8(table.slots.len() as u8);
    for slot in &table.slots {
        out.identity(slot.member.identity);
        out.u64(slot.retired_through);
        out.binding(&slot.member);
        out.u8(slot.phase as u8);
        out.u8(u8::from(slot.last_result.is_some()));
        if let Some(result) = &slot.last_result {
            out.bytes(result.request_id.as_bytes());
            out.bytes(&result.request_digest);
            out.u64(result.incarnation.get());
            out.u64(result.revision);
            out.u64(result.configuration_epoch.get());
            out.u8(result.kind as u8);
            out.log_id(result.terminal);
        }
    }
    out.u8(u8::from(table.replacement.is_some()));
    if let Some(operation) = &table.replacement {
        out.u64(operation.expected_revision);
        let attestation = encode_lost_voter_attestation(&operation.attestation)?;
        out.sized_bytes(&attestation)?;
        out.configuration(&operation.predecessor);
        out.configuration(&operation.successor);
        out.u8(operation.phase as u8);
        let evidence = &operation.evidence;
        out.log_id(evidence.prepare);
        out.u8(u8::from(evidence.snapshot.is_some()));
        if let Some(snapshot) = &evidence.snapshot {
            out.log_id(snapshot.cut);
            out.sized_bytes(snapshot.snapshot_id.as_bytes())?;
            out.bytes(&snapshot.digest);
        }
        for cut in [
            evidence.learner,
            evidence.caught_up,
            evidence.continuation,
            evidence.fence,
            evidence.joint,
            evidence.uniform,
        ] {
            out.u8(u8::from(cut.is_some()));
            if let Some(cut) = cut {
                out.log_id(cut);
            }
        }
    }
    if out.0.len() > MAX_VOTER_SLOT_TABLE_BYTES {
        return Err(VoterSlotError::TooLarge);
    }
    Ok(out.0)
}

/// Decode bounded canonical data; this never constructs authorization or admission.
pub fn decode_voter_slot_table(bytes: &[u8]) -> Result<VoterSlotTable, VoterSlotError> {
    let mut input = Reader::new(bytes, MAX_VOTER_SLOT_TABLE_BYTES)?;
    let magic = input.array::<4>()?;
    let version = input.u16()?;
    if &magic != FORMAT {
        return Err(VoterSlotError::InvalidRecord);
    }
    if version != VERSION {
        return Err(VoterSlotError::FreshInstallationRequired);
    }
    let cluster_instance = ConsensusClusterId::from_bytes(input.array()?);
    let manifest_digest = input.array()?;
    let revision = input.u64()?;
    let configuration_epoch = input.epoch()?;
    let count = input.count()?;
    let mut slots = Vec::with_capacity(count);
    for _ in 0..count {
        let identity = input.identity()?;
        let retired_through = input.u64()?;
        let member = input.binding(identity)?;
        let phase = match input.u8()? {
            0 => VoterSlotPhase::Pending,
            1 => VoterSlotPhase::CatchingUp,
            2 => VoterSlotPhase::Voting,
            _ => return Err(VoterSlotError::InvalidRecord),
        };
        let last_result = input.optional(|input| {
            Ok(VoterReplacementResult {
                request_id: ConsensusRequestId::from_bytes(input.array()?),
                request_digest: input.array()?,
                incarnation: input.incarnation()?,
                revision: input.u64()?,
                configuration_epoch: input.epoch()?,
                kind: match input.u8()? {
                    0 => VoterReplacementResultKind::Completed,
                    1 => VoterReplacementResultKind::Superseded,
                    _ => return Err(VoterSlotError::InvalidRecord),
                },
                terminal: input.log_id()?,
            })
        })?;
        slots.push(VoterSlotRecord {
            member,
            retired_through,
            phase,
            last_result,
        });
    }
    let replacement = input.optional(|input| {
        let expected_revision = input.u64()?;
        let claims = input.sized_bytes(MAX_LOST_VOTER_ATTESTATION_BYTES)?;
        let attestation = decode_lost_voter_attestation(claims)?;
        let predecessor = input.configuration()?;
        let successor = input.configuration()?;
        let phase = match input.u8()? {
            0 => VoterReplacementPhase::Prepared,
            1 => VoterReplacementPhase::SnapshotInstalled,
            2 => VoterReplacementPhase::LearnerAdded,
            3 => VoterReplacementPhase::CaughtUp,
            4 => VoterReplacementPhase::Fenced,
            5 => VoterReplacementPhase::Joint,
            6 => VoterReplacementPhase::Uniform,
            _ => return Err(VoterSlotError::InvalidRecord),
        };
        let evidence = VoterReplacementEvidence {
            prepare: input.log_id()?,
            snapshot: input.optional(|input| {
                Ok(VoterSnapshotEvidence {
                    cut: input.log_id()?,
                    snapshot_id: input.string(MAX_VOTER_SNAPSHOT_ID_BYTES)?,
                    digest: input.array()?,
                })
            })?,
            learner: input.optional(Reader::log_id)?,
            caught_up: input.optional(Reader::log_id)?,
            continuation: input.optional(Reader::log_id)?,
            fence: input.optional(Reader::log_id)?,
            joint: input.optional(Reader::log_id)?,
            uniform: input.optional(Reader::log_id)?,
        };
        Ok(VoterReplacementRecord {
            expected_revision,
            attestation,
            predecessor,
            successor,
            phase,
            evidence,
        })
    })?;
    input.finish()?;
    let table = VoterSlotTable {
        cluster_instance,
        manifest_digest,
        revision,
        configuration_epoch,
        slots,
        replacement,
    };
    table.validate()?;
    Ok(table)
}

/// Encode bounded claims and signature with the RFC 023 unsigned big-endian layout.
pub fn encode_lost_voter_attestation(
    claims: &LostVoterAttestationV1,
) -> Result<Vec<u8>, VoterSlotError> {
    let mut out = unsigned_claims(claims, true)?;
    out.bytes(&claims.signature);
    if out.0.len() > MAX_LOST_VOTER_ATTESTATION_BYTES {
        return Err(VoterSlotError::TooLarge);
    }
    Ok(out.0)
}

/// Exact message to sign with ECDSA P-256/SHA-256: the RFC 023 domain followed
/// by canonical unsigned claims. It includes the request digest and excludes
/// the signature. This function neither signs nor verifies the attestation.
pub fn lost_voter_attestation_signing_input(
    claims: &LostVoterAttestationV1,
) -> Result<Vec<u8>, VoterSlotError> {
    let mut out = Writer(ATTESTATION_SIGNING_DOMAIN.to_vec());
    out.bytes(&unsigned_claims(claims, true)?.0);
    Ok(out.0)
}

/// Compute the canonical request digest shared by controllers and both stores.
///
/// SHA-256 covers the request domain, `u16` version 1, expected revision, exact
/// predecessor identity (cluster/configuration/epoch), selected candidate
/// (slot/incarnation/key/descriptor/generation), then unsigned attestation claims
/// with the request-digest field omitted. Integers use fixed-width big endian.
/// The digest and signature are excluded to avoid circularity; transport proofs
/// and credentials are not part of this body. Authorization remains external.
pub fn voter_replacement_request_digest(
    expected_revision: u64,
    expected_configuration: ConsensusIdentity,
    candidate: &VoterSlotMember,
    claims: &LostVoterAttestationV1,
) -> Result<[u8; 32], VoterSlotError> {
    if expected_revision == 0
        || expected_configuration.cluster_id() != claims.cluster_instance
        || candidate.identity.slot() != claims.slot
        || candidate.identity.incarnation() != claims.expected_incarnation.next()?
        || candidate.key_digest != claims.candidate_key_digest
        || candidate.admission_generation != claims.admission_generation
    {
        return Err(VoterSlotError::InvalidRecord);
    }
    let mut out = Writer(REPLACEMENT_REQUEST_DOMAIN.to_vec());
    out.u16(VERSION);
    out.u64(expected_revision);
    out.bytes(expected_configuration.cluster_id().as_bytes());
    out.bytes(expected_configuration.configuration_id().as_bytes());
    out.u64(expected_configuration.configuration_epoch().get());
    out.identity(candidate.identity);
    out.binding(candidate);
    out.bytes(&unsigned_claims(claims, false)?.0);
    Ok(Sha256::digest(out.0).into())
}

fn unsigned_claims(
    claims: &LostVoterAttestationV1,
    include_digest: bool,
) -> Result<Writer, VoterSlotError> {
    claims.validate()?;
    let mut out = Writer(Vec::new());
    out.u16(VERSION);
    out.bytes(claims.request_id.as_bytes());
    if include_digest {
        out.bytes(&claims.request_digest);
    }
    out.bytes(claims.cluster_instance.as_bytes());
    out.u16(claims.slot.get());
    out.u64(claims.expected_incarnation.get());
    out.bytes(&claims.old_descriptor_digest);
    out.bytes(&claims.candidate_key_digest);
    out.u64(claims.admission_generation);
    out.sized_bytes(claims.candidate_spiffe_id.as_bytes())?;
    out.sized_bytes(claims.controller_spiffe_id.as_bytes())?;
    out.bytes(&claims.signing_key_digest);
    out.u8(claims.reason as u8);
    out.bytes(&claims.policy_digest);
    out.u64(claims.observation_start_ms);
    out.u64(claims.decision_ms);
    out.u64(claims.issued_ms);
    out.u64(claims.expires_ms);
    Ok(out)
}

/// Decode untrusted claims; cryptographic verification belongs to trusted admission.
pub fn decode_lost_voter_attestation(
    bytes: &[u8],
) -> Result<LostVoterAttestationV1, VoterSlotError> {
    let mut input = Reader::new(bytes, MAX_LOST_VOTER_ATTESTATION_BYTES)?;
    if input.u16()? != VERSION {
        return Err(VoterSlotError::InvalidRecord);
    }
    let record = LostVoterAttestationV1 {
        request_id: ConsensusRequestId::from_bytes(input.array()?),
        request_digest: input.array()?,
        cluster_instance: ConsensusClusterId::from_bytes(input.array()?),
        slot: SlotId::new(input.u16()?)?,
        expected_incarnation: input.incarnation()?,
        old_descriptor_digest: input.array()?,
        candidate_key_digest: input.array()?,
        admission_generation: input.u64()?,
        candidate_spiffe_id: input.identity_string()?,
        controller_spiffe_id: input.identity_string()?,
        signing_key_digest: input.array()?,
        reason: match input.u8()? {
            1 => VoterLossReason::StorageLost,
            2 => VoterLossReason::TimeBoundLoss,
            _ => return Err(VoterSlotError::InvalidRecord),
        },
        policy_digest: input.array()?,
        observation_start_ms: input.u64()?,
        decision_ms: input.u64()?,
        issued_ms: input.u64()?,
        expires_ms: input.u64()?,
        signature: input.array()?,
    };
    input.finish()?;
    record.validate()?;
    Ok(record)
}

struct Writer(Vec<u8>);

impl Writer {
    fn bytes(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }
    fn u16(&mut self, value: u16) {
        self.bytes(&value.to_be_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }
    fn sized_bytes(&mut self, value: &[u8]) -> Result<(), VoterSlotError> {
        self.u16(u16::try_from(value.len()).map_err(|_| VoterSlotError::TooLarge)?);
        self.bytes(value);
        Ok(())
    }
    fn identity(&mut self, identity: VoterSlotIdentity) {
        self.u16(identity.slot().get());
        self.u64(identity.incarnation().get());
    }
    fn binding(&mut self, member: &VoterSlotMember) {
        self.bytes(&member.key_digest);
        self.bytes(&member.descriptor_digest);
        self.u64(member.admission_generation);
    }
    fn configuration(&mut self, config: &VoterConfiguration) {
        self.u64(config.epoch.get());
        self.u8(config.members.len() as u8);
        for member in &config.members {
            self.identity(member.identity);
            self.binding(member);
        }
    }
    fn log_id(&mut self, id: VoterSlotLogId) {
        self.u64(id.term);
        self.u64(id.index);
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], bound: usize) -> Result<Self, VoterSlotError> {
        if bytes.len() > bound {
            return Err(VoterSlotError::TooLarge);
        }
        Ok(Self(bytes))
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], VoterSlotError> {
        let (prefix, rest) = self
            .0
            .split_at_checked(count)
            .ok_or(VoterSlotError::InvalidRecord)?;
        self.0 = rest;
        Ok(prefix)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], VoterSlotError> {
        self.take(N)?
            .try_into()
            .map_err(|_| VoterSlotError::InvalidRecord)
    }
    fn u8(&mut self) -> Result<u8, VoterSlotError> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, VoterSlotError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, VoterSlotError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn epoch(&mut self) -> Result<ConsensusConfigurationEpoch, VoterSlotError> {
        ConsensusConfigurationEpoch::new(self.u64()?).map_err(|_| VoterSlotError::InvalidRecord)
    }
    fn incarnation(&mut self) -> Result<VoterIncarnation, VoterSlotError> {
        VoterIncarnation::new(self.u64()?)
    }
    fn identity(&mut self) -> Result<VoterSlotIdentity, VoterSlotError> {
        Ok(VoterSlotIdentity::new(
            SlotId::new(self.u16()?)?,
            self.incarnation()?,
        ))
    }
    fn count(&mut self) -> Result<usize, VoterSlotError> {
        let count = usize::from(self.u8()?);
        super::validation::validate_count(count)?;
        Ok(count)
    }
    fn binding(&mut self, identity: VoterSlotIdentity) -> Result<VoterSlotMember, VoterSlotError> {
        Ok(VoterSlotMember {
            identity,
            key_digest: self.array()?,
            descriptor_digest: self.array()?,
            admission_generation: self.u64()?,
        })
    }
    fn configuration(&mut self) -> Result<VoterConfiguration, VoterSlotError> {
        let epoch = self.epoch()?;
        let count = self.count()?;
        let mut members = Vec::with_capacity(count);
        for _ in 0..count {
            let identity = self.identity()?;
            members.push(self.binding(identity)?);
        }
        Ok(VoterConfiguration { epoch, members })
    }
    fn optional<T>(
        &mut self,
        read: impl FnOnce(&mut Self) -> Result<T, VoterSlotError>,
    ) -> Result<Option<T>, VoterSlotError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(read(self)?)),
            _ => Err(VoterSlotError::InvalidRecord),
        }
    }
    fn log_id(&mut self) -> Result<VoterSlotLogId, VoterSlotError> {
        Ok(VoterSlotLogId {
            term: self.u64()?,
            index: self.u64()?,
        })
    }
    fn sized_bytes(&mut self, bound: usize) -> Result<&'a [u8], VoterSlotError> {
        let count = usize::from(self.u16()?);
        if count > bound {
            return Err(VoterSlotError::TooLarge);
        }
        self.take(count)
    }
    fn identity_string(&mut self) -> Result<String, VoterSlotError> {
        self.string(MAX_VOTER_SPIFFE_ID_BYTES)
    }
    fn string(&mut self, bound: usize) -> Result<String, VoterSlotError> {
        let bytes = self.sized_bytes(bound)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| VoterSlotError::InvalidRecord)
    }
    fn finish(self) -> Result<(), VoterSlotError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(VoterSlotError::InvalidRecord)
        }
    }
}
