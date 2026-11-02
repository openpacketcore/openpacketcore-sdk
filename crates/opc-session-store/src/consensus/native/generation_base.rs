//! Streaming complete bases. This borrows an immutable full capture;
//! the caller must prepare/encode it outside State and own its output file.
//! It writes no selector, grants no writer authority, and reclaims nothing.
//! Cold admission requires Catalog::open. A live immutable capture can instead
//! admit complete expected readback, without allocating a second resident index.

#[cfg(test)]
use super::super::prefix::CompareWriter;
use super::*;

pub(super) const MAGIC: &[u8; 8] = b"OPCNJB\x07\x00";
pub(super) const SLOT_MAGIC: &[u8; 8] = b"OPCNJB\x07\x01";
pub(super) const V4_MAGIC: &[u8; 8] = b"OPCNJ004";
pub(super) const V5_MAGIC: &[u8; 8] = b"OPCNJ005";
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
    fn capture(
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
        let format = if header.context.business.frontiers.voter_slots.is_some() {
            Format::V7_SLOTS
        } else {
            Format::V7
        };
        Ok(Self {
            storage,
            header,
            payload_bytes: 0,
            length: 0,
            format,
            _memory: memory,
        })
    }

    pub(crate) fn prepare(
        storage: &'a NativeStorage,
        parameters: BaseParameters,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        let maximum = parameters.maximum;
        let block_bytes = parameters.block_bytes;
        let mut value = Self::capture(storage, parameters, check)?;
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
        #[cfg(test)]
        super::super::rollover_costs::record(|costs| costs.serializations += 1);
        check()?;
        writer.write_all(match self.format {
            Format::V2 => LEGACY_MAGIC,
            Format::V3 => V3_MAGIC,
            Format::V4 => V4_MAGIC,
            Format::V5 => V5_MAGIC,
            Format::V6 => b"OPCNJB\x06\x00",
            Format::V6_SLOTS => b"OPCNJB\x06\x01",
            Format::V7 => MAGIC,
            Format::V7_SLOTS => SLOT_MAGIC,
            _ => return Err(invalid("native generation discriminator differs")),
        })?;
        let header = encode_header(&self.header)?;
        write_bytes(writer, &header, MAX_HEADER)?;
        for (key, row) in &self.storage.business.keys {
            check()?;
            writer.write_all(&[0])?;
            write_before(writer, None)?;
            if self.format.vocabulary >= Format::V7.vocabulary {
                write_binary(writer, &(key, Some(&**row)))?;
            } else {
                write_binary(
                    writer,
                    &(key, Some(key_codec::BeforeEpoch::from_current(row)?)),
                )?;
            }
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
        if self.format.vocabulary >= Format::V4.vocabulary {
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
        self,
        maximum: u64,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        self.format_for_test(Format::V2, maximum, check)
    }

    #[cfg(test)]
    pub(super) fn format_for_test(
        mut self,
        format: Format,
        maximum: u64,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        format.validate_context(&self.header.context)?;
        self.format = format;
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

/// A captured canonical stream without a counting traversal or persisted input.
pub(crate) struct StreamingBase<'a>(PreparedBase<'a>);

impl<'a> StreamingBase<'a> {
    pub(crate) fn prepare(
        storage: &'a NativeStorage,
        parameters: BaseParameters,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        PreparedBase::capture(storage, parameters, check).map(Self)
    }

    // Exclusive read sections remain covered by their security regressions.
    // Production compaction always uses the concurrent ordinary read path.
    #[cfg(test)]
    pub(crate) fn write_new(
        &self,
        file: std::fs::File,
        maximum: u64,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<super::super::prefix::Created> {
        if let Some(origin) = &self.0.storage.business.snapshot_origin {
            origin.verify()?;
        }
        let created = super::super::prefix::with_read_section(|| {
            super::super::prefix::Created::encode(
                file,
                self.0.identity([0; 32])?,
                maximum,
                check,
                |writer| self.0.write_payload(writer, check),
            )
        })?;
        if let Some(origin) = &self.0.storage.business.snapshot_origin {
            origin.verify()?;
        }
        Ok(created)
    }

    /// Concurrent append ownership stays on the old source. Use its ordinary
    /// per-read metadata and block authentication; no read section is entered.
    pub(crate) fn write_new_concurrent(
        &self,
        file: std::fs::File,
        maximum: u64,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<super::super::prefix::Created> {
        if let Some(origin) = &self.0.storage.business.snapshot_origin {
            origin.verify()?;
        }
        let created = super::super::prefix::Created::encode(
            file,
            self.0.identity([0; 32])?,
            maximum,
            check,
            |writer| self.0.write_payload(writer, check),
        )?;
        if let Some(origin) = &self.0.storage.business.snapshot_origin {
            origin.verify()?;
        }
        Ok(created)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct CountedReader<'a> {
        input: Cursor<&'a [u8]>,
        reads: usize,
    }

    impl Read for CountedReader<'_> {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            self.input.read(bytes)
        }
    }

    fn position_dependent_bytes() -> Vec<u8> {
        (0..2 * 8192 + 17)
            .map(|position| (position ^ (position >> 8) ^ (position >> 13)) as u8)
            .collect()
    }

    #[test]
    fn native_base_readback_batches_small_canonical_fields() {
        let expected = position_dependent_bytes();
        let mut input = CountedReader {
            input: Cursor::new(expected.as_slice()),
            reads: 0,
        };
        {
            let mut writer = CompareWriter::new(&mut input);
            // Framing emits individual tag bytes. Verified-prefix reads must
            // scale with bounded buffers, not the number of framing fields.
            for byte in &expected {
                writer.write_all(std::slice::from_ref(byte)).unwrap();
            }
        }
        assert_eq!(input.input.position(), expected.len() as u64);
        assert!(
            input.reads <= expected.len().div_ceil(8192),
            "small fields caused {} authenticated reads for {} bytes",
            input.reads,
            expected.len(),
        );
    }

    #[test]
    fn native_base_readback_rejects_corruption_across_buffer_boundaries() {
        let expected = position_dependent_bytes();
        for write_size in [expected.len(), 1, 31] {
            for corrupt_at in [0, 17, 8191, 8192, 8209, 16383, expected.len() - 1] {
                let mut actual = expected.clone();
                actual[corrupt_at] ^= 1;
                let mut input = Cursor::new(actual);
                let mut writer = CompareWriter::new(&mut input);
                let result = expected
                    .chunks(write_size)
                    .try_for_each(|chunk| writer.write_all(chunk));
                assert_eq!(
                    result.expect_err("corruption must be compared").kind(),
                    io::ErrorKind::InvalidData,
                    "corrupt offset {corrupt_at}, write size {write_size}"
                );
            }
            for truncated_at in [0, 17, 8191, 8192, expected.len() - 1] {
                let mut input = Cursor::new(&expected[..truncated_at]);
                let mut writer = CompareWriter::new(&mut input);
                let result = expected
                    .chunks(write_size)
                    .try_for_each(|chunk| writer.write_all(chunk));
                assert_eq!(
                    result.expect_err("truncation must be rejected").kind(),
                    io::ErrorKind::UnexpectedEof,
                    "truncated offset {truncated_at}, write size {write_size}"
                );
            }
        }
    }

    fn assert_failed_refill_does_not_reuse_consumed_bytes(failure: io::ErrorKind) {
        struct FailedRefill {
            first: Cursor<[u8; 8192]>,
            failure: io::ErrorKind,
        }

        impl Read for FailedRefill {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                if self.first.position() < 8192 {
                    return self.first.read(bytes);
                }
                if self.failure == io::ErrorKind::UnexpectedEof {
                    Ok(0)
                } else {
                    Err(self.failure.into())
                }
            }
        }

        let mut input = FailedRefill {
            first: Cursor::new([0x5a; 8192]),
            failure,
        };
        let mut writer = CompareWriter::new(&mut input);
        writer.write_all(&[0x5a; 8192]).expect("first chunk");
        assert_eq!(writer.write(&[0x5a; 17]).unwrap_err().kind(), failure);
        assert_eq!(
            writer
                .write(&[0x5a; 17])
                .expect_err("retry must refill, not compare consumed bytes")
                .kind(),
            failure,
        );
        assert_eq!(writer.position, 0);
        assert_eq!(writer.available, 0);
    }

    #[test]
    fn native_base_readback_refill_error_does_not_reuse_consumed_bytes() {
        assert_failed_refill_does_not_reuse_consumed_bytes(io::ErrorKind::WouldBlock);
    }

    #[test]
    fn native_base_readback_refill_eof_does_not_reuse_consumed_bytes() {
        assert_failed_refill_does_not_reuse_consumed_bytes(io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn native_base_readback_retries_interruptions_and_accepts_short_reads() {
        struct ShortReader<'a> {
            input: Cursor<&'a [u8]>,
            interrupt_next: bool,
        }

        impl Read for ShortReader<'_> {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                if self.interrupt_next {
                    self.interrupt_next = false;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                self.interrupt_next = true;
                let count = bytes.len().min(7);
                self.input.read(&mut bytes[..count])
            }
        }

        let expected = position_dependent_bytes();
        let mut input = ShortReader {
            input: Cursor::new(expected.as_slice()),
            interrupt_next: true,
        };
        {
            let mut writer = CompareWriter::new(&mut input);
            assert_eq!(writer.write(&[]).unwrap(), 0);
            for chunk in expected.chunks(31) {
                writer.write_all(chunk).unwrap();
            }
        }
        assert_eq!(input.input.position(), expected.len() as u64);
    }
}
