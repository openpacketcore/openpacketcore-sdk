//! Complete after-image transactions for a V4 native generation owner.
//!
//! This layer encodes one detached, certified change capture and verifies its
//! complete readback through the append-prefix owner. It grants byte admission
//! only: neither CURRENT nor a resident row is changed here. The integrating
//! WAL owner must bind the prior selected generation/version, select the exact
//! new checkpoint durably, and only then evict or reclaim. Cold reconstruction
//! of an arbitrary generation is a separate reader, not this expected-readback
//! interface. Existing OPCNAT01/02 readers remain explicit full-image readers.

use super::image::binary;
use super::prefix::{PrefixIdentity, VerifiedAppendOwner, VerifiedPrefix};
use super::*;
use crate::consensus::verified_snapshot::VerificationMemory;
use opc_consensus::engine::Vote;
use sha2::{Digest as _, Sha256};
use std::io::{Read, Write};
use std::sync::Arc;
use zeroize::Zeroizing;

#[path = "generation_base.rs"]
mod base;
#[path = "generation_catalog.rs"]
mod catalog;
#[path = "generation_decode.rs"]
pub(super) mod decode;
#[path = "generation_header.rs"]
mod header;
#[path = "generation_restore.rs"]
mod restore;
#[path = "generation_sqlite.rs"]
mod sqlite;
use restore::BaseRestore;
#[path = "generation_relocation.rs"]
mod relocation;
pub(crate) use relocation::Relocations;
pub(in crate::consensus::native) use relocation::{PositionedReader, RelocationBuilder};
#[path = "generation_facts.rs"]
pub(super) mod facts;
pub(crate) use base::PreparedBase;
pub(crate) use catalog::Catalog;
pub(crate) use sqlite::SqlitePreparedBase;

const MAGIC: &[u8; 8] = b"OPCNJD04";
const V3_MAGIC: &[u8; 8] = b"OPCNJD03";
const LEGACY_MAGIC: &[u8; 8] = b"OPCNJD02";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Format {
    V2,
    V3,
    V4,
}

impl Format {
    fn read(reader: &mut dyn Read, base: bool) -> io::Result<Self> {
        let mut magic = [0; 8];
        reader.read_exact(&mut magic)?;
        if &magic == if base { base::MAGIC } else { MAGIC } {
            Ok(Self::V4)
        } else if &magic == if base { base::V3_MAGIC } else { V3_MAGIC } {
            Ok(Self::V3)
        } else if &magic
            == if base {
                base::LEGACY_MAGIC
            } else {
                LEGACY_MAGIC
            }
        {
            Ok(Self::V2)
        } else {
            Err(invalid("native generation discriminator differs"))
        }
    }

    fn validate_context(self, context: &Context) -> io::Result<()> {
        if self != Self::V4
            && (context.business.roster.is_some()
                || context.business.frontiers.roster_v1_namespace
                || context.business.frontiers.roster_v2_activation.is_some())
        {
            return Err(invalid(
                "native roster context requires its complete generation vocabulary",
            ));
        }
        if self == Self::V4
            && context.business.roster.is_none()
            && (context.business.frontiers.roster_v1_namespace
                || context.business.frontiers.roster_v2_activation.is_some())
        {
            return Err(invalid("native roster generation context is absent"));
        }
        if self == Self::V2 && context.business.frontiers.v1_activation.is_some() {
            return Err(invalid(
                "native V1 context requires generation format three",
            ));
        }
        Ok(())
    }
}
const END: &[u8; 8] = b"OPCNJEND";
const MAX_HEADER: usize = 64 * 1024;
pub(super) const MAX_ITEM: usize =
    2 * crate::sqlite::consensus::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES;
const HEADER_MEMORY: usize = 8 * MAX_HEADER;

// Allocate once before writing any local restore key. Bounded output prevents
// Vec growth from leaving earlier key-bearing allocations behind.
fn encode_header(value: &impl Serialize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(MAX_HEADER)
        .map_err(|_| invalid("native header allocation failed"))?;
    let mut output = base::Output {
        writer: &mut *bytes,
        hash: Sha256::new(),
        position: 0,
        maximum: MAX_HEADER as u64,
    };
    serde_json::to_writer(&mut output, value)
        .map_err(|_| invalid("native generation header exceeds encoding bound"))?;
    Ok(bytes)
}

/// Admit the separate caller-supplied snapshot metadata before the original
/// installer allocates an encoding. The same native header ceiling covers
/// the temporary encodings and the origin's retained, fixed-membership clone.
pub(crate) fn reserve_install_metadata(
    snapshot: &crate::sqlite::consensus::CurrentSnapshot,
    path: &std::path::Path,
) -> io::Result<VerificationMemory> {
    reserve_install_metadata_parts(&snapshot.0, &snapshot.1, snapshot.2, snapshot.3, path)
}

pub(crate) fn reserve_install_metadata_parts(
    meta: &opc_consensus::engine::SnapshotMeta<
        SessionConsensusNodeId,
        opc_consensus::engine::EmptyNode,
    >,
    name: &str,
    checksum: [u8; 32],
    length: u64,
    path: &std::path::Path,
) -> io::Result<VerificationMemory> {
    validation::validate_snapshot_metadata_parts(&meta.snapshot_id, name, length)?;
    let membership = meta.last_membership.membership();
    if membership.get_joint_config().len() > 1
        || membership.voter_ids().take(6).count() > 5
        || membership.nodes().take(6).count() > 5
        || path.as_os_str().len() > MAX_HEADER
    {
        return Err(invalid(
            "native install candidate metadata exceeds fixed header contract",
        ));
    }
    let mut sink = io::sink();
    let mut bounded = base::Output {
        writer: &mut sink,
        hash: Sha256::new(),
        position: 0,
        maximum: MAX_HEADER as u64,
    };
    serde_json::to_writer(&mut bounded, &(meta, name, checksum, length))
        .map_err(|_| invalid("native install candidate metadata exceeds header bound"))?;
    VerificationMemory::reserve(HEADER_MEMORY)
}

/// These are persisted comparison values. No revision address or process
/// certificate is serialized. Cold reconstruction must derive all counts and
/// content summaries itself and independently validate every retained row.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BusinessContext {
    pub(super) identity: SessionConsensusIdentity,
    pub(super) members: BTreeSet<SessionConsensusNodeId>,
    pub(super) frontiers: NativeFrontiers,
    pub(super) counts: [usize; 4],
    pub(super) content: [[u8; 32]; 4],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) roster: Option<RosterContext>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RosterContext {
    // Comparison only. Opening always receives the independently configured
    // verifier root; generation bytes cannot choose a public key.
    pub(super) root: Option<[u8; 32]>,
    pub(super) counts: [usize; 2],
    pub(super) content: [[u8; 32]; 2],
    pub(super) witness: Option<crate::fenced_mutation_roster_storage::GlobalChargeWitness>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LogContext {
    pub(super) vote: Option<Vote<SessionConsensusNodeId>>,
    pub(super) committed: Option<LogId<SessionConsensusNodeId>>,
    pub(super) purged: Option<LogId<SessionConsensusNodeId>>,
    pub(super) count: usize,
    pub(super) content: [u8; 32],
    pub(super) first: Option<LogId<SessionConsensusNodeId>>,
    pub(super) last: Option<LogId<SessionConsensusNodeId>>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    business: BusinessContext,
    log: LogContext,
}

struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Context {
    fn digest(&self) -> io::Result<[u8; 32]> {
        let mut writer = HashWriter(Sha256::new());
        writer.write_all(b"OPC-native-generation-context-v1\0")?;
        serde_json::to_writer(&mut writer, self)
            .map_err(|_| invalid("native generation context cannot encode"))?;
        Ok(writer.0.finalize().into())
    }
}

/// Strong, process-only predecessor ownership. Capturing it is bounded; it
/// contains no row containers and cannot be constructed by deserialization.
#[derive(Clone)]
pub(crate) struct Version {
    business: Arc<changes::BusinessProof>,
    log: log::GenerationLogVersion,
}

impl Version {
    pub(crate) fn capture(storage: &NativeStorage) -> io::Result<Self> {
        Ok(Self {
            business: Arc::clone(storage.business.require_business_proof()?),
            log: storage.log.generation_version(&storage.business)?,
        })
    }

    pub(crate) fn require_current(&self, storage: &NativeStorage) -> io::Result<()> {
        let current = Self::capture(storage)?;
        if !Arc::ptr_eq(&self.business, &current.business) || !self.log.same(&current.log) {
            return Err(invalid("native generation process predecessor changed"));
        }
        Ok(())
    }

    fn context(&self) -> Context {
        Context {
            business: self.business.generation_context(),
            log: self.log.context(),
        }
    }

    // Detached work: context cloning/hash serialization is never part of the
    // bounded State-lock capture. The caller reserves before those allocations.
    pub(crate) fn context_digest(&self) -> io::Result<[u8; 32]> {
        let _memory = VerificationMemory::reserve(HEADER_MEMORY)?;
        self.context().digest()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Previous {
    binding: [u8; 32],
    file_epoch: u64,
    checkpoint_epoch: u64,
    operation_sequence: u64,
    frontiers: [u8; 32],
    length: u64,
    block_bytes: usize,
    digest: [u8; 32],
}

impl From<PrefixIdentity> for Previous {
    fn from(value: PrefixIdentity) -> Self {
        Self {
            binding: value.binding,
            file_epoch: value.file_epoch,
            checkpoint_epoch: value.checkpoint_epoch,
            operation_sequence: value.operation_sequence,
            frontiers: value.frontiers,
            length: value.length,
            block_bytes: value.block_bytes,
            digest: value.digest,
        }
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    previous: Previous,
    checkpoint_epoch: u64,
    operation_sequence: u64,
    // Digest of the complete canonical WAL cut/selector comparison fields.
    // The WAL layer must supply and recheck that exact tuple at selection;
    // this field is neither a durable-cut certificate nor apply authority.
    cut_binding: [u8; 32],
    before: Context,
    after: Context,
    changed: [usize; 5],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    roster_changed: Option<[usize; 2]>,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseHeader {
    binding: [u8; 32],
    file_epoch: u64,
    checkpoint_epoch: u64,
    operation_sequence: u64,
    block_bytes: usize,
    cut_binding: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_restore: Option<BaseRestore>,
    context: Context,
}

struct Counter {
    bytes: u64,
}
impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| invalid("native generation extent overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One immutable expected transaction. It retains its capture and header
/// reservation through encoding/readback/error/unwind. It returns no decoded
/// row, so a response/record/Bytes clone cannot escape a scratch reservation.
pub(crate) struct PreparedDelta {
    capture: NativeChanges,
    previous: Arc<VerifiedPrefix>,
    target: Version,
    header: Header,
    payload_bytes: u64,
    _memory: VerificationMemory,
}

impl PreparedDelta {
    pub(crate) fn prepare(
        previous: Arc<VerifiedPrefix>,
        current: &Version,
        checkpoint_epoch: u64,
        operation_sequence: u64,
        cut_binding: [u8; 32],
        capture: NativeChanges,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        check()?;
        let memory = VerificationMemory::reserve(HEADER_MEMORY)?;
        capture.validate(check)?;
        if let Some(origin) = current.business.snapshot_origin() {
            origin.verify()?;
        }
        if !capture.business.generation_starts_at(&current.business)
            || !capture.log.generation_starts_at(&current.log)
        {
            return Err(invalid(
                "native generation capture has a different process predecessor",
            ));
        }
        let before = current.context();
        let old = previous.identity();
        if before.digest()? != old.frontiers
            || old.checkpoint_epoch.checked_add(1) != Some(checkpoint_epoch)
            || checkpoint_epoch == u64::MAX
            || operation_sequence < old.operation_sequence
        {
            return Err(invalid("native generation selected predecessor differs"));
        }
        let target = Version {
            business: Arc::clone(capture.business.target_proof()),
            log: capture.log.generation_target(),
        };
        let header = Header {
            previous: old.into(),
            checkpoint_epoch,
            operation_sequence,
            cut_binding,
            before,
            after: target.context(),
            changed: capture
                .business
                .generation_counts(capture.log.generation_count()),
            roster_changed: Some(capture.business.generation_roster_counts()),
        };
        let mut value = Self {
            capture,
            previous,
            target,
            header,
            payload_bytes: 0,
            _memory: memory,
        };
        let mut counter = Counter { bytes: 0 };
        value.write_payload(&mut counter, check)?;
        value.payload_bytes = counter.bytes;
        check()?;
        Ok(value)
    }

    pub(crate) fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }
    pub(crate) fn target_version(&self) -> Version {
        self.target.clone()
    }

    fn write_payload(
        &self,
        writer: &mut dyn Write,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        check()?;
        let bytes = serde_json::to_vec(&self.header)
            .map_err(|_| invalid("native generation header cannot encode"))?;
        writer.write_all(MAGIC)?;
        write_bytes(writer, &bytes, MAX_HEADER)?;
        self.capture.business.write_generation(writer, check)?;
        self.capture.log.write_generation(writer, check)?;
        self.capture
            .business
            .write_roster_generation(writer, check)?;
        writer.write_all(END)?;
        check()
    }

    fn verify_payload(
        &self,
        reader: &mut dyn Read,
        check: &impl Fn() -> io::Result<()>,
        mut relocations: Option<&mut RelocationBuilder>,
    ) -> io::Result<()> {
        check()?;
        let mut positioned = PositionedReader::new(reader, self.previous.identity().length);
        let reader = &mut positioned;
        expect(reader, MAGIC)?;
        {
            let input = read_bytes(reader, MAX_HEADER)?;
            // This is expected readback: bind the complete canonical header
            // before deserializing nested membership or snapshot metadata.
            // Untrusted input cannot supply a larger allocation shape than
            // the already-certified header covered by our reservation.
            let expected = serde_json::to_vec(&self.header)
                .map_err(|_| invalid("native generation header cannot encode"))?;
            if input.bytes() != expected {
                return Err(invalid(
                    "native generation header bytes differ from captured checkpoint",
                ));
            }
            drop(expected);
            let header: Header = serde_json::from_slice(input.bytes())
                .map_err(|_| invalid("native generation header invalid"))?;
            if header != self.header
                || serde_json::to_vec(&header)
                    .map_err(|_| invalid("native generation header cannot reencode"))?
                    != input.bytes()
            {
                return Err(invalid(
                    "native generation header differs from captured checkpoint",
                ));
            }
        }
        self.capture
            .business
            .verify_generation(reader, check, relocations.as_deref_mut())?;
        self.capture
            .log
            .verify_generation(reader, check, relocations.as_deref_mut())?;
        self.capture
            .business
            .verify_roster_generation(reader, check, relocations)?;
        expect(reader, END)?;
        let mut extra = [0; 1];
        if reader.read(&mut extra)? != 0 {
            return Err(invalid(
                "native generation transaction contains trailing bytes",
            ));
        }
        check()
    }

    /// Only byte admission advances here. The integrating WAL owner retains
    /// the old selected cut and all reconstruction rows until CURRENT fsync.
    pub(crate) fn append(
        &self,
        owner: &mut VerifiedAppendOwner,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Arc<VerifiedPrefix>> {
        owner.append(
            &self.previous,
            self.header.checkpoint_epoch,
            self.header.operation_sequence,
            self.header.after.digest()?,
            self.payload_bytes,
            check,
            |writer| self.write_payload(writer, check),
            |reader| self.verify_payload(reader, check, None),
        )
    }

    pub(crate) fn append_with_relocations(
        &self,
        owner: &mut VerifiedAppendOwner,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<(Arc<VerifiedPrefix>, Relocations)> {
        let maximum = self.header.changed[1]
            .checked_add(self.header.changed[3])
            .and_then(|count| count.checked_add(self.header.changed[4]))
            .and_then(|count| {
                count.checked_add(self.header.roster_changed.map_or(0, |counts| counts[0]))
            })
            .ok_or_else(|| invalid("native relocation captured count overflow"))?;
        let mut rows = RelocationBuilder::new(maximum)?;
        let source = owner.append(
            &self.previous,
            self.header.checkpoint_epoch,
            self.header.operation_sequence,
            self.header.after.digest()?,
            self.payload_bytes,
            check,
            |writer| self.write_payload(writer, check),
            |reader| self.verify_payload(reader, check, Some(&mut rows)),
        )?;
        let relocations = rows.prepare(
            Arc::clone(&source),
            self.header.after.business.identity,
            &self.header.after.business.members,
            self.capture.business.target_proof().roster_root(),
            check,
        )?;
        Ok((source, relocations))
    }
}

pub(super) fn write_bytes(writer: &mut dyn Write, bytes: &[u8], maximum: usize) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(invalid("native generation row length invalid"));
    }
    let length =
        u32::try_from(bytes.len()).map_err(|_| invalid("native generation row length overflow"))?;
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(bytes)
}

pub(super) struct Input {
    // Field order refunds only after the complete input buffer is destroyed,
    // including early errors and unwinding in a verifier.
    bytes: Zeroizing<Vec<u8>>,
    _memory: VerificationMemory,
}
impl Input {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub(super) fn read_bytes(reader: &mut dyn Read, maximum: usize) -> io::Result<Input> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > maximum {
        return Err(invalid("native generation row length invalid"));
    }
    let memory = VerificationMemory::reserve(length)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .map_err(|_| invalid("native generation input allocation failed"))?;
    bytes.resize(length, 0);
    reader.read_exact(&mut bytes)?;
    Ok(Input {
        bytes,
        _memory: memory,
    })
}

pub(super) fn expect(reader: &mut dyn Read, expected: &[u8]) -> io::Result<()> {
    // Includes the complete original 120-byte roster binding.
    if expected.len() > 120 {
        return Err(invalid("native generation scalar width invalid"));
    }
    let mut bytes = [0; 120];
    reader.read_exact(&mut bytes[..expected.len()])?;
    if &bytes[..expected.len()] != expected {
        return Err(invalid("native generation scalar differs"));
    }
    Ok(())
}

pub(super) fn write_before(writer: &mut dyn Write, before: Option<[u8; 32]>) -> io::Result<()> {
    writer.write_all(&[u8::from(before.is_some())])?;
    if let Some(before) = before {
        writer.write_all(&before)?;
    }
    Ok(())
}

pub(super) fn expect_before(reader: &mut dyn Read, before: Option<[u8; 32]>) -> io::Result<()> {
    expect(reader, &[u8::from(before.is_some())])?;
    if let Some(before) = before {
        expect(reader, &before)?;
    }
    Ok(())
}

pub(super) fn write_binary(writer: &mut dyn Write, value: &impl Serialize) -> io::Result<()> {
    let length = binary::encoded_len(value, MAX_ITEM)?;
    if length == 0 {
        return Err(invalid("native generation binary row empty"));
    }
    writer.write_all(&(length as u32).to_le_bytes())?;
    if binary::write_to(value, writer, length)? != length {
        return Err(invalid("native generation binary extent differs"));
    }
    Ok(())
}

// This expected-readback helper first proves every byte equals the complete
// canonical encoding of the already-certified typed capture. Only then can
// its existing shape/allocation bound be used for decoding. It is NOT an
// arbitrary cold-generation parser and returns no value or borrowed callback.
pub(super) fn verify_binary<T: serde::de::DeserializeOwned + Serialize>(
    reader: &mut dyn Read,
    expected: &impl Serialize,
) -> io::Result<()> {
    let length = binary::encoded_len(expected, MAX_ITEM)?;
    let input = read_bytes(reader, length)?;
    binary::compare(expected, input.bytes())?;
    let decoded: T = binary::decode(input.bytes())?;
    drop(decoded);
    Ok(())
}

pub(super) fn payload_scratch(
    payload: usize,
    check: &impl Fn() -> io::Result<()>,
    verify: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    check()?;
    let bytes = payload
        .checked_mul(6)
        .and_then(|bytes| bytes.checked_add(64 * 1024))
        .ok_or_else(|| invalid("native generation decoder reservation overflow"))?;
    let _memory = VerificationMemory::reserve(bytes)?;
    verify()?;
    check()
}

#[cfg(test)]
#[path = "generation_tests.rs"]
mod tests;
