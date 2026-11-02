//! A fresh canonical stream, compared as written and authenticated after sync.
//! This constructor cannot admit a persisted comparison tuple or an old file.

use super::*;

pub(crate) struct Created {
    source: Arc<VerifiedAppendSource>,
    identity: PrefixIdentity,
    readback: Zeroizing<Vec<u8>>,
    _scratch: VerificationMemory,
}

impl Created {
    pub(crate) fn encode(
        file: File,
        mut identity: PrefixIdentity,
        maximum: u64,
        check: &impl Fn() -> io::Result<()>,
        encode: impl FnOnce(&mut dyn Write) -> io::Result<()>,
    ) -> io::Result<Self> {
        let maximum = maximum.min(maximum_length(identity.block_bytes)?);
        identity.length = identity.block_bytes as u64;
        identity.validate(maximum)?;
        let before = MetadataIdentity::read(&file.metadata()?)?;
        if before.length != 0 {
            return Err(invalid());
        }
        identity.length = 0;
        let source = VerifiedAppendSource::allocate(file, before, identity, maximum)?;
        let scratch = VerificationMemory::reserve(
            identity.block_bytes.checked_add(8192).ok_or_else(invalid)?,
        )?;
        let mut writer = Blocks {
            source: &source,
            output: buffer(identity.block_bytes)?,
            used: 0,
            written: 0,
            check,
        };
        encode(&mut writer)?;
        if writer.used != 0 {
            writer.output[writer.used..].fill(0);
            writer.flush_block()?;
        }
        identity.length = writer.written;
        identity.validate(maximum)?;
        let metadata = MetadataIdentity::read(&source.file.metadata()?)?;
        if !before.same_file(metadata) || metadata.length != identity.length {
            return Err(invalid());
        }
        drop(writer);
        let readback = buffer(8192)?;
        Ok(Self {
            source,
            identity,
            readback,
            _scratch: scratch,
        })
    }

    pub(crate) fn file(&self) -> &File {
        &self.source.file
    }

    /// Every byte was compared with the single canonical encoding. Revalidate
    /// its expected block commitments AFTER sync and rename: changes since the
    /// byte comparison cannot become selected authority. Derive the full-file
    /// digest here once, rather than hashing another canonical serialization.
    pub(crate) fn admit(
        mut self,
        path: &Path,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<VerifiedAppendOwner> {
        let mut fence = FailureFence::new(&self.source.failed);
        let before = MetadataIdentity::read(&self.source.file.metadata()?)?;
        if !self.source.pinned.same_file(before) || before.length != self.identity.length {
            return Err(invalid());
        }
        let mut hasher = Sha256::new();
        for index in 0..self.identity.blocks(self.source.maximum)? {
            check()?;
            let mut block_hash = Sha256::new();
            for inside in (0..self.identity.block_bytes).step_by(self.readback.len()) {
                let count = self.readback.len().min(self.identity.block_bytes - inside);
                self.source.file.read_exact_at(
                    &mut self.readback[..count],
                    index as u64 * self.identity.block_bytes as u64 + inside as u64,
                )?;
                block_hash.update(&self.readback[..count]);
                hasher.update(&self.readback[..count]);
            }
            if <[u8; 32]>::from(block_hash.finalize()) != self.source.digest(index)? {
                return Err(invalid());
            }
            #[cfg(test)]
            crate::consensus::native::rollover_costs::record(|costs| {
                costs.authenticated_output_blocks += 1
            });
        }
        check()?;
        let named = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        if MetadataIdentity::read(&named.metadata()?)? != before
            || MetadataIdentity::read(&self.source.file.metadata()?)? != before
        {
            return Err(invalid());
        }
        self.identity.digest = hasher.clone().finalize().into();
        self.source
            .admitted_length
            .store(self.identity.length, Ordering::Release);
        fence.accept();
        drop(fence);
        let current = VerifiedPrefix::allocate(self.source, self.identity)?;
        Ok(VerifiedAppendOwner {
            current,
            hasher,
            opened: None,
        })
    }
}

struct Blocks<'a> {
    source: &'a VerifiedAppendSource,
    output: Zeroizing<Vec<u8>>,
    used: usize,
    written: u64,
    check: &'a dyn Fn() -> io::Result<()>,
}

impl Blocks<'_> {
    fn flush_block(&mut self) -> io::Result<()> {
        #[cfg(test)]
        crate::consensus::native::rollover_costs::adapter(
            crate::consensus::native::rollover_costs::Adapter::BaseBlock,
        );
        (self.check)()?;
        let next = self
            .written
            .checked_add(self.source.block_bytes as u64)
            .filter(|next| *next <= self.source.maximum)
            .ok_or_else(capacity_limit)?;
        let index = usize::try_from(self.written / self.source.block_bytes as u64)
            .map_err(|_| invalid())?;
        if index % PAGE_BLOCKS == 0 {
            self.source.pages[index / PAGE_BLOCKS]
                .set(DigestPage::allocate()?)
                .map_err(|_| invalid())?;
        }
        self.source.file.write_all_at(&self.output, self.written)?;
        let mut reader = AtOffset {
            file: &self.source.file,
            position: self.written,
        };
        CompareWriter::new(&mut reader).write_all(&self.output)?;
        self.source
            .fill(index, Sha256::digest(&*self.output).into())?;
        #[cfg(test)]
        crate::consensus::native::rollover_costs::record(|costs| costs.output_blocks += 1);
        self.written = next;
        self.used = 0;
        Ok(())
    }
}

impl Write for Blocks<'_> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len();
        self.written
            .checked_add(self.used as u64)
            .and_then(|n| n.checked_add(count as u64))
            .filter(|end| *end <= self.source.maximum)
            .ok_or_else(capacity_limit)?;
        while !bytes.is_empty() {
            let copy = bytes.len().min(self.output.len() - self.used);
            self.output[self.used..self.used + copy].copy_from_slice(&bytes[..copy]);
            self.used += copy;
            bytes = &bytes[copy..];
            if self.used == self.output.len() {
                self.flush_block()?;
            }
        }
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct AtOffset<'a> {
    file: &'a File,
    position: u64,
}
impl Read for AtOffset<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.file.read_at(output, self.position)?;
        self.position = self
            .position
            .checked_add(count as u64)
            .ok_or_else(invalid)?;
        Ok(count)
    }
}
