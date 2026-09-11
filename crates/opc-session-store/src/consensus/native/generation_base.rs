//! Streaming complete V4 bases. This borrows an immutable full capture;
//! the caller must prepare/encode it outside State and own its output file.
//! It writes no selector, grants no writer authority, and reclaims nothing.
//! Admission requires Catalog::open to read and validate the entire result.

use super::*;

pub(super) const MAGIC: &[u8; 8] = b"OPCNJ004";
pub(super) const V3_MAGIC: &[u8; 8] = b"OPCNJ003";
pub(super) const LEGACY_MAGIC: &[u8; 8] = b"OPCNJ002";

/// Exact caller-supplied generation identity, durable cut and output bounds.
pub(crate) struct BaseParameters {
    /// Binding of this generation to its native owner.
    pub(crate) binding: [u8; 32],
    /// Identity of the newly created generation file.
    pub(crate) file_epoch: u64,
    /// Checkpoint selected by this complete base.
    pub(crate) checkpoint_epoch: u64,
    /// Native operation sequence represented by this base.
    pub(crate) operation_sequence: u64,
    /// Independently supplied binding of the exact committed cut.
    pub(crate) cut_binding: [u8; 32],
    /// Verification block width, validated before alignment arithmetic.
    pub(crate) block_bytes: usize,
    /// Existing maximum encoded generation length.
    pub(crate) maximum: u64,
}

pub(crate) struct PreparedBase<'a> {
    storage: &'a NativeStorage,
    header: BaseHeader,
    payload_bytes: u64,
    length: u64,
    format: Format,
    _memory: VerificationMemory,
}

impl<'a> PreparedBase<'a> {
    pub(crate) fn prepare(
        storage: &'a NativeStorage,
        parameters: BaseParameters,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        let BaseParameters {
            binding,
            file_epoch,
            checkpoint_epoch,
            operation_sequence,
            cut_binding,
            block_bytes,
            maximum,
        } = parameters;
        check()?;
        let memory = VerificationMemory::reserve(HEADER_MEMORY)?;
        let version = Version::capture(storage)?;
        let context = version.context();
        catalog::validate_context_header_with_origin(
            &context,
            binding,
            storage.business.identity,
            &storage.business.members,
            storage.business.roster_root.as_deref(),
            storage.business.snapshot_origin.as_deref(),
        )?;
        if let Some(origin) = &storage.business.snapshot_origin {
            origin.verify()?;
        }
        // Validate the width/epochs before any alignment arithmetic.
        PrefixIdentity {
            binding,
            file_epoch,
            checkpoint_epoch,
            operation_sequence,
            frontiers: context.digest()?,
            length: block_bytes as u64,
            block_bytes,
            digest: [0; 32],
        }
        .blocks(maximum)?;
        let native_restore = storage
            .business
            .snapshot_origin
            .as_deref()
            .map(BaseRestore::from_origin);
        let header = BaseHeader {
            binding,
            file_epoch,
            checkpoint_epoch,
            operation_sequence,
            block_bytes,
            cut_binding,
            native_restore,
            context,
        };
        let mut value = Self {
            storage,
            header,
            payload_bytes: 0,
            length: 0,
            format: Format::V4,
            _memory: memory,
        };
        let mut counter = Counter { bytes: 0 };
        value.write_payload(&mut counter, check)?;
        value.payload_bytes = counter.bytes;
        let block = block_bytes as u64;
        value.length = counter
            .bytes
            .checked_add(block - 1)
            .map(|bytes| bytes / block * block)
            .ok_or_else(|| invalid("native generation base alignment overflow"))?;
        value.identity([0; 32])?.blocks(maximum)?;
        check()?;
        Ok(value)
    }

    fn identity(&self, digest: [u8; 32]) -> io::Result<PrefixIdentity> {
        Ok(PrefixIdentity {
            binding: self.header.binding,
            file_epoch: self.header.file_epoch,
            checkpoint_epoch: self.header.checkpoint_epoch,
            operation_sequence: self.header.operation_sequence,
            frontiers: self.header.context.digest()?,
            length: self.length,
            block_bytes: self.header.block_bytes,
            digest,
        })
    }

    fn write_payload(
        &self,
        writer: &mut dyn Write,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        check()?;
        writer.write_all(match self.format {
            Format::V2 => LEGACY_MAGIC,
            Format::V3 => V3_MAGIC,
            Format::V4 => MAGIC,
        })?;
        let header = encode_header(&self.header)?;
        write_bytes(writer, &header, MAX_HEADER)?;
        for (key, row) in &self.storage.business.keys {
            check()?;
            writer.write_all(&[0])?;
            write_before(writer, None)?;
            write_binary(writer, &(key, Some(&**row)))?;
        }
        for (id, row) in &self.storage.business.receipts {
            check()?;
            writer.write_all(&[1])?;
            write_before(writer, None)?;
            writer.write_all(&id.to_bytes())?;
            writer.write_all(&[1])?;
            let resolved = row
                .cold_range()
                .map(|(source, range)| {
                    cold::ReceiptReadTicket::capture(&self.storage.business, *id, source, range)?
                        .resolve(check)?
                        .copy_guarded(&self.storage.business)
                })
                .transpose()?;
            let row = resolved
                .as_ref()
                .map(cold::OwnedReceipt::row)
                .unwrap_or(row);
            let length = cold::write_receipt(&mut io::sink(), *id, row, check)?;
            writer.write_all(&(length as u32).to_le_bytes())?;
            if cold::write_receipt(writer, *id, row, check)? != length {
                return Err(invalid("native generation base receipt extent changed"));
            }
        }
        for (id, row) in &self.storage.business.generic_receipts {
            check()?;
            changes::generic_payload(Some(row))?;
            writer.write_all(&[2])?;
            write_before(writer, None)?;
            if self.format == Format::V2 {
                let NativeGenericReceipt::Ordinary(row) = &**row else {
                    return Err(invalid("legacy generation cannot encode V1 receipts"));
                };
                write_binary(writer, &(id, Some(row)))?;
            } else {
                write_binary(writer, &(id, Some(&**row)))?;
            }
        }
        for row in &self.storage.business.notifications {
            check()?;
            writer.write_all(&[3])?;
            row.write_binary(writer, &self.storage.business.frontiers, check)?;
        }
        for (index, row) in &self.storage.log.entries {
            check()?;
            writer.write_all(&[4])?;
            writer.write_all(&index.to_le_bytes())?;
            write_before(writer, None)?;
            writer.write_all(&[1])?;
            let bytes = row.read_bytes(
                self.storage.business.identity,
                &self.storage.business.members,
                check,
            )?;
            write_bytes(
                writer,
                bytes.bytes(),
                crate::sqlite::consensus::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES,
            )?;
        }
        if self.format == Format::V4 {
            roster::generation::write_base(
                &self.storage.business.roster,
                writer,
                self.storage.business.roster_root.as_deref(),
                &roster::fixed_scope(
                    self.storage.business.identity,
                    &self.storage.business.members,
                ),
                check,
            )?;
        }
        writer.write_all(END)?;
        check()
    }

    #[cfg(test)]
    pub(super) fn legacy_for_test(
        mut self,
        maximum: u64,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        Format::V2.validate_context(&self.header.context)?;
        self.format = Format::V2;
        let mut counter = Counter { bytes: 0 };
        self.write_payload(&mut counter, check)?;
        self.payload_bytes = counter.bytes;
        let block = self.header.block_bytes as u64;
        self.length = counter
            .bytes
            .checked_add(block - 1)
            .map(|bytes| bytes / block * block)
            .ok_or_else(|| invalid("legacy generation alignment overflow"))?;
        self.identity([0; 32])?.blocks(maximum)?;
        Ok(self)
    }

    /// Writes exactly the counted payload and canonical block padding. The
    /// returned digest is a comparison input; the caller must sync its pinned
    /// output and perform complete cold admission before using the generation.
    pub(crate) fn write_to(
        &self,
        writer: &mut dyn Write,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<PrefixIdentity> {
        if let Some(origin) = &self.storage.business.snapshot_origin {
            origin.verify()?;
        }
        let mut output = Output {
            writer,
            hash: Sha256::new(),
            position: 0,
            maximum: self.length,
        };
        self.write_payload(&mut output, check)?;
        if output.position != self.payload_bytes {
            return Err(invalid("native generation base payload extent changed"));
        }
        let padding = [0; 4096];
        while output.position < self.length {
            check()?;
            let count = usize::try_from(self.length - output.position)
                .unwrap_or(usize::MAX)
                .min(padding.len());
            output.write_all(&padding[..count])?;
        }
        check()?;
        if let Some(origin) = &self.storage.business.snapshot_origin {
            origin.verify()?;
        }
        self.identity(output.hash.finalize().into())
    }
}

pub(super) struct Output<'a> {
    pub(super) writer: &'a mut dyn Write,
    pub(super) hash: Sha256,
    pub(super) position: u64,
    pub(super) maximum: u64,
}
impl Write for Output<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self
            .position
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= self.maximum)
            .ok_or_else(|| invalid("native generation base output exceeds counted extent"))?;
        self.writer.write_all(bytes)?;
        self.hash.update(bytes);
        self.position = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
