//! One immutable traversal with descriptor bookends and a private verified cache.
//! The caller must keep append ownership detached until this section finishes.

use super::*;
use std::cell::RefCell;

thread_local! {
    static SECTION: RefCell<Option<Section>> = const { RefCell::new(None) };
}

struct Section {
    source: Option<Arc<VerifiedAppendSource>>,
    before: Option<MetadataIdentity>,
    cache: Option<CachedBlocks>,
    memory: Option<VerificationMemory>,
}

impl Section {
    fn finish_source(&mut self) -> io::Result<()> {
        if let Some(source) = self.source.take() {
            let mut fence = FailureFence::new(&source.failed);
            if Some(source.metadata()?) != self.before.take() {
                return Err(invalid());
            }
            fence.accept();
        }
        self.cache = None;
        self.memory = None;
        Ok(())
    }

    fn read(
        &mut self,
        source: &Arc<VerifiedAppendSource>,
        length: u64,
        offset: u64,
        output: &mut [u8],
    ) -> io::Result<()> {
        let end = offset
            .checked_add(output.len() as u64)
            .filter(|end| *end <= length)
            .ok_or_else(invalid)?;
        if !self
            .source
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, source))
        {
            self.finish_source()?;
            self.memory = Some(VerificationMemory::reserve(
                source.block_bytes.checked_mul(2).ok_or_else(invalid)?,
            )?);
            self.before = Some(source.metadata()?);
            self.cache = Some(CachedBlocks::allocate(source.block_bytes)?);
            self.source = Some(Arc::clone(source));
        }
        let mut fence = FailureFence::new(&source.failed);
        let cache = self.cache.as_mut().ok_or_else(invalid)?;
        let mut position = offset;
        let mut written = 0;
        while position < end {
            let index =
                usize::try_from(position / source.block_bytes as u64).map_err(|_| invalid())?;
            let hit = cache
                .blocks
                .iter()
                .position(|block| block.metadata == self.before && block.index == index);
            let slot = match hit {
                Some(slot) => slot,
                None => {
                    let slot = 1 - cache.recent;
                    let block = &mut cache.blocks[slot];
                    block.metadata = None;
                    if block.bytes.is_empty() {
                        block.bytes = buffer(source.block_bytes)?;
                    }
                    source.file.read_exact_at(
                        &mut block.bytes,
                        index as u64 * source.block_bytes as u64,
                    )?;
                    #[cfg(test)]
                    source.blocks_read.fetch_add(1, Ordering::Relaxed);
                    if <[u8; 32]>::from(Sha256::digest(&*block.bytes)) != source.digest(index)? {
                        return Err(invalid());
                    }
                    block.metadata = self.before;
                    block.index = index;
                    slot
                }
            };
            cache.recent = slot;
            let inside = (position % source.block_bytes as u64) as usize;
            let count = (source.block_bytes - inside).min(output.len() - written);
            output[written..written + count]
                .copy_from_slice(&cache.blocks[slot].bytes[inside..inside + count]);
            position += count as u64;
            written += count;
        }
        fence.accept();
        Ok(())
    }
}

struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        SECTION.with(|slot| {
            if let Some(mut section) = slot.borrow_mut().take() {
                let _ = section.finish_source();
            }
        });
    }
}

pub(crate) fn with_read_section<T>(read: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    let nested = SECTION.with(|slot| slot.borrow().is_some());
    if nested {
        return read();
    }
    SECTION.with(|slot| {
        *slot.borrow_mut() = Some(Section {
            source: None,
            before: None,
            cache: None,
            memory: None,
        })
    });
    let _guard = Guard;
    let result = read();
    let finished = SECTION.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .ok_or_else(invalid)?
            .finish_source()
    });
    result.and_then(|value| finished.map(|()| value))
}

pub(super) fn read(
    source: &Arc<VerifiedAppendSource>,
    length: u64,
    offset: u64,
    output: &mut [u8],
) -> Option<io::Result<()>> {
    SECTION.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .map(|section| section.read(source, length, offset, output))
    })
}
