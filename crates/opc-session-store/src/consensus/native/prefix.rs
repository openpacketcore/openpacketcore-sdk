//! Process-admitted, append-only byte prefixes. This is deliberately separate
//! from `VerifiedFile`: extending a file must not weaken fixed-file admission.
//!
//! The one owner keeps the SHA state; views share write-once digest pages and
//! cannot extend them. Persisted identities are comparison inputs, never a
//! certificate. Cold admission hashes and decodes the entire selected prefix.
//! An extension encodes, syncs, verifies, and decodes only its new extent.
//!
//! All methods that do I/O, allocate, decode, or wait for the cache mutex must
//! run OUTSIDE the SDK State lock. A view certifies bytes, not current business
//! authority. Its consumer must separately recheck the captured row revision
//! and authority under State before linearizing a live read or publication.
//! This module neither selects CURRENT nor repairs/reclaims any file.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::consensus::verified_snapshot::VerificationMemory;

const MIN_BLOCK: usize = 64 * 1024;
const MAX_BLOCK: usize = 2 * 1024 * 1024;
const MAX_BLOCKS: usize = 16 * 1024 * 1024 / 32;
const PAGE_BLOCKS: usize = 256;
const INDEX_PAGES: usize = MAX_BLOCKS / PAGE_BLOCKS;
const ARC_HEADER: usize = 2 * size_of::<usize>();

#[cfg_attr(feature = "test-control", track_caller)]
fn invalid() -> io::Error {
    #[cfg(feature = "test-control")]
    eprintln!(
        "native_prefix_validation_failure source={}",
        std::panic::Location::caller()
    );
    io::Error::new(
        io::ErrorKind::InvalidData,
        "native prefix integrity check failed",
    )
}

fn buffer(bytes: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(bytes).map_err(|_| invalid())?;
    buffer.resize(bytes, 0);
    Ok(Zeroizing::new(buffer))
}

/// Exact persisted comparison tuple. `frontiers` binds the canonical complete
/// application/log/authority/snapshot frontiers, validated by the format layer.
/// File generation, checkpoint epoch and WAL sequence are separate axes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PrefixIdentity {
    pub(crate) binding: [u8; 32],
    pub(crate) file_epoch: u64,
    pub(crate) checkpoint_epoch: u64,
    pub(crate) operation_sequence: u64,
    pub(crate) frontiers: [u8; 32],
    pub(crate) length: u64,
    pub(crate) block_bytes: usize,
    pub(crate) digest: [u8; 32],
}

/// Exact new cut and payload extent for one append transaction.
pub(crate) struct AppendTransaction {
    /// Checkpoint immediately following the admitted predecessor.
    pub(crate) checkpoint_epoch: u64,
    /// Native operation sequence represented by the new checkpoint.
    pub(crate) operation_sequence: u64,
    /// Commitment to all resulting application and log frontiers.
    pub(crate) frontiers: [u8; 32],
    /// Complete encoded transaction length before canonical padding.
    pub(crate) payload_bytes: u64,
}

impl PrefixIdentity {
    pub(crate) fn validate(self, maximum: u64) -> io::Result<()> {
        self.blocks(maximum).map(|_| ())
    }

    pub(super) fn blocks(self, maximum: u64) -> io::Result<usize> {
        if !(MIN_BLOCK..=MAX_BLOCK).contains(&self.block_bytes)
            || !self.block_bytes.is_power_of_two()
            || self.length == 0
            || self.length > maximum
            || !self.length.is_multiple_of(self.block_bytes as u64)
            || self.file_epoch == u64::MAX
            || self.checkpoint_epoch == u64::MAX
        {
            return Err(invalid());
        }
        usize::try_from(self.length / self.block_bytes as u64)
            .ok()
            .filter(|count| *count <= MAX_BLOCKS)
            .ok_or_else(invalid)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct MetadataIdentity {
    device: u64,
    inode: u64,
    length: u64,
    ctime: i64,
    ctime_nsec: i64,
}

impl MetadataIdentity {
    fn read(metadata: &Metadata) -> io::Result<Self> {
        if !metadata.is_file() || metadata.nlink() == 0 {
            return Err(invalid());
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        })
    }

    fn same_file(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

// Pages and every digest slot are write-once. A new view retains the source,
// not a copy of the old index. Empty slots in the final page may be filled by
// its sole owner; no previously admitted digest is ever replaced. The fixed
// page directory avoids index rebuilding or pointer copying during append.
struct DigestPage {
    digests: [OnceLock<[u8; 32]>; PAGE_BLOCKS],
    _memory: VerificationMemory,
}

impl DigestPage {
    fn allocate() -> io::Result<Box<Self>> {
        let memory = VerificationMemory::reserve(size_of::<Self>())?;
        Ok(Box::new(Self {
            digests: std::array::from_fn(|_| OnceLock::new()),
            _memory: memory,
        }))
    }
}

struct CachedBlock {
    metadata: Option<MetadataIdentity>,
    index: usize,
    bytes: Zeroizing<Vec<u8>>,
}

struct CachedBlocks {
    recent: usize,
    blocks: [CachedBlock; 2],
    evicted: Option<(MetadataIdentity, usize)>,
}

impl CachedBlocks {
    fn allocate(bytes: usize) -> io::Result<Self> {
        Ok(Self {
            recent: 0,
            blocks: [
                CachedBlock {
                    metadata: None,
                    index: 0,
                    bytes: buffer(bytes)?,
                },
                CachedBlock {
                    metadata: None,
                    index: 0,
                    bytes: Zeroizing::new(Vec::new()),
                },
            ],
            evicted: None,
        })
    }
}

pub(crate) struct VerifiedAppendSource {
    file: File,
    pinned: MetadataIdentity,
    maximum: u64,
    block_bytes: usize,
    pages: Vec<OnceLock<Box<DigestPage>>>,
    admitted_length: AtomicU64,
    failed: AtomicBool,
    cache: Mutex<Option<CachedBlocks>>,
    #[cfg(test)]
    blocks_read: AtomicU64,
    // Source, owner SHA state, page directory, and both verified cache buffers.
    // Digest pages, views, capture/append scratch reserve separately from the
    // SAME process-wide VerificationMemory counter before allocation.
    _memory: VerificationMemory,
}

impl VerifiedAppendSource {
    fn allocate(
        file: File,
        pinned: MetadataIdentity,
        identity: PrefixIdentity,
        maximum: u64,
    ) -> io::Result<Arc<Self>> {
        let memory_bytes = size_of::<Self>()
            .checked_add(size_of::<VerifiedAppendOwner>())
            .and_then(|n| n.checked_add(ARC_HEADER))
            .and_then(|n| {
                n.checked_add(INDEX_PAGES.checked_mul(size_of::<OnceLock<Box<DigestPage>>>())?)
            })
            .and_then(|n| n.checked_add(identity.block_bytes.checked_mul(2)?))
            .ok_or_else(invalid)?;
        let memory = VerificationMemory::reserve(memory_bytes)?;
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(INDEX_PAGES)
            .map_err(|_| invalid())?;
        pages.resize_with(INDEX_PAGES, OnceLock::new);
        Ok(Arc::new(Self {
            file,
            pinned,
            maximum,
            block_bytes: identity.block_bytes,
            pages,
            admitted_length: AtomicU64::new(identity.length),
            failed: AtomicBool::new(false),
            cache: Mutex::new(None),
            #[cfg(test)]
            blocks_read: AtomicU64::new(0),
            _memory: memory,
        }))
    }

    fn metadata(&self) -> io::Result<MetadataIdentity> {
        if self.failed.load(Ordering::Acquire) {
            return Err(invalid());
        }
        let metadata = MetadataIdentity::read(&self.file.metadata()?)?;
        if !self.pinned.same_file(metadata)
            || metadata.length < self.admitted_length.load(Ordering::Acquire)
            || metadata.length > self.maximum
        {
            return Err(invalid());
        }
        Ok(metadata)
    }

    fn digest(&self, index: usize) -> io::Result<[u8; 32]> {
        self.pages
            .get(index / PAGE_BLOCKS)
            .and_then(OnceLock::get)
            .and_then(|page| page.digests[index % PAGE_BLOCKS].get())
            .copied()
            .ok_or_else(invalid)
    }

    fn fill(&self, index: usize, digest: [u8; 32]) -> io::Result<()> {
        self.pages
            .get(index / PAGE_BLOCKS)
            .and_then(OnceLock::get)
            .ok_or_else(invalid)?
            .digests[index % PAGE_BLOCKS]
            .set(digest)
            .map_err(|_| invalid())
    }

    fn read(&self, length: u64, offset: u64, output: &mut [u8]) -> io::Result<()> {
        let end = offset
            .checked_add(output.len() as u64)
            .filter(|end| *end <= length)
            .ok_or_else(invalid)?;
        let mut fence = FailureFence::new(&self.failed);
        self.metadata()?;
        let mut cache = self.cache.lock().map_err(|_| invalid())?;
        let mut position = offset;
        let mut written = 0;
        while position < end {
            let metadata = self.metadata()?;
            let index =
                usize::try_from(position / self.block_bytes as u64).map_err(|_| invalid())?;
            let hit = cache.as_ref().and_then(|cache| {
                cache
                    .blocks
                    .iter()
                    .position(|block| block.index == index && block.metadata == Some(metadata))
            });
            let slot = if let Some(slot) = hit {
                cache.as_mut().ok_or_else(invalid)?.recent = slot;
                slot
            } else {
                // A miss replaces every byte before authentication. Transfer
                // both zeroizing buffers out of the cache and reuse the less
                // recent block. Alternating two blocks uses the same original
                // two-buffer reservation without repeatedly reading/hashing
                // either one. Errors drop/wipe both buffers and fence every
                // view; partially read or unverified bytes cannot be cached.
                let mut next = match cache.take() {
                    Some(previous) => previous,
                    None => CachedBlocks::allocate(self.block_bytes)?,
                };
                let older = 1 - next.recent;
                // A sequential admission needs only one buffer. Allocate the
                // reserved second buffer when a reader comes back to the last
                // evicted block; this key is only an allocation hint. Every
                // miss still reads and authenticates the complete block below.
                let slot = if next.blocks[older].bytes.is_empty()
                    && next.evicted != Some((metadata, index))
                {
                    next.recent
                } else {
                    older
                };
                let block = &mut next.blocks[slot];
                next.evicted = block.metadata.map(|metadata| (metadata, block.index));
                block.metadata = None;
                if block.bytes.is_empty() {
                    block.bytes = buffer(self.block_bytes)?;
                }
                self.file
                    .read_exact_at(&mut block.bytes, index as u64 * self.block_bytes as u64)?;
                #[cfg(test)]
                self.blocks_read.fetch_add(1, Ordering::Relaxed);
                let actual: [u8; 32] = Sha256::digest(&*block.bytes).into();
                if actual != self.digest(index)? {
                    return Err(invalid());
                }
                // Metadata is only a cache hint. The owned verified bytes
                // stay exact even if the file changes immediately afterward.
                block.metadata = Some(metadata);
                block.index = index;
                next.recent = slot;
                *cache = Some(next);
                slot
            };
            let cached = &cache.as_ref().ok_or_else(invalid)?.blocks[slot];
            let inside = (position % self.block_bytes as u64) as usize;
            let count = (self.block_bytes - inside).min(output.len() - written);
            output[written..written + count].copy_from_slice(&cached.bytes[inside..inside + count]);
            position += count as u64;
            written += count;
        }
        self.metadata()?;
        fence.accept();
        Ok(())
    }
}

struct FailureFence<'a> {
    failed: &'a AtomicBool,
    accepted: bool,
}
impl<'a> FailureFence<'a> {
    fn new(failed: &'a AtomicBool) -> Self {
        Self {
            failed,
            accepted: false,
        }
    }
    fn accept(&mut self) {
        self.accepted = true;
    }
}
impl Drop for FailureFence<'_> {
    fn drop(&mut self) {
        if !self.accepted {
            self.failed.store(true, Ordering::Release);
        }
    }
}

/// Immutable range authority. Cloning its Arc shares both metadata and index;
/// even the oldest live view charges the whole pinned generation until drop.
pub(crate) struct VerifiedPrefix {
    source: Arc<VerifiedAppendSource>,
    identity: PrefixIdentity,
    _memory: VerificationMemory,
}

impl VerifiedPrefix {
    fn allocate(
        source: Arc<VerifiedAppendSource>,
        identity: PrefixIdentity,
    ) -> io::Result<Arc<Self>> {
        let memory = VerificationMemory::reserve(size_of::<Self>() + ARC_HEADER)?;
        Ok(Arc::new(Self {
            source,
            identity,
            _memory: memory,
        }))
    }

    pub(crate) fn identity(&self) -> PrefixIdentity {
        self.identity
    }

    // A process-local ordering hint only. All views of one append source
    // share its cache even when they certify different immutable prefixes.
    // A caller must still read through its own exact view and validate rows.
    pub(super) fn source_order(&self) -> usize {
        Arc::as_ptr(&self.source) as usize
    }

    #[cfg(test)]
    pub(super) fn blocks_read(&self) -> u64 {
        self.source.blocks_read.load(Ordering::Relaxed)
    }

    pub(crate) fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        self.source.read(self.identity.length, offset, output)
    }

    pub(crate) fn reader(self: &Arc<Self>) -> PrefixReader {
        PrefixReader {
            view: Arc::clone(self),
            position: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn is_failed(&self) -> bool {
        self.source.failed.load(Ordering::Acquire)
    }
}

pub(crate) struct PrefixReader {
    view: Arc<VerifiedPrefix>,
    position: u64,
}
impl Read for PrefixReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = usize::try_from(self.view.identity.length - self.position)
            .unwrap_or(usize::MAX)
            .min(output.len());
        self.view
            .read_exact_at(self.position, &mut output[..count])?;
        self.position += count as u64;
        Ok(count)
    }
}

/// Only this non-cloneable owner can append. A byte proof does not publish a
/// checkpoint: the WAL owner still must validate exact live frontiers and
/// durably select CURRENT before evicting rows or reclaiming any predecessor.
pub(crate) struct VerifiedAppendOwner {
    current: Arc<VerifiedPrefix>,
    hasher: Sha256,
    // Exact descriptor metadata after complete cold admission. It authorizes
    // no repair by itself; the WAL opener first admits strict snapshots and
    // the complete durable suffix, then calls repair_unselected_tail.
    opened: Option<MetadataIdentity>,
}

impl VerifiedAppendOwner {
    /// The parent directory is already admitted by the WAL directory owner.
    /// Opening the final component never follows a symlink or blocks on a FIFO.
    /// Unselected tail bytes remain untouched and are not semantic authority.
    pub(crate) fn open(
        path: &Path,
        expected: PrefixIdentity,
        maximum: u64,
        mut check: impl FnMut() -> io::Result<()>,
        validate: impl FnOnce(&mut PrefixReader) -> io::Result<()>,
    ) -> io::Result<Self> {
        let count = expected.blocks(maximum)?;
        check()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let before = MetadataIdentity::read(&file.metadata()?)?;
        if before.length < expected.length || before.length > maximum {
            return Err(invalid());
        }
        let source = VerifiedAppendSource::allocate(file, before, expected, maximum)?;
        let _scratch = VerificationMemory::reserve(expected.block_bytes)?;
        let mut bytes = buffer(expected.block_bytes)?;
        let mut hasher = Sha256::new();
        for index in 0..count {
            check()?;
            if index % PAGE_BLOCKS == 0 {
                source.pages[index / PAGE_BLOCKS]
                    .set(DigestPage::allocate()?)
                    .map_err(|_| invalid())?;
            }
            source
                .file
                .read_exact_at(&mut bytes, index as u64 * expected.block_bytes as u64)?;
            hasher.update(&*bytes);
            source.fill(index, Sha256::digest(&*bytes).into())?;
        }
        let digest: [u8; 32] = hasher.clone().finalize().into();
        if digest != expected.digest || source.metadata()? != before {
            return Err(invalid());
        }
        drop(bytes);
        drop(_scratch);
        let current = VerifiedPrefix::allocate(source, expected)?;
        let mut reader = current.reader();
        validate(&mut reader)?;
        check()?;
        if reader.position != expected.length || current.source.metadata()? != before {
            return Err(invalid());
        }
        Ok(Self {
            current,
            hasher,
            opened: Some(before),
        })
    }

    pub(crate) fn current(&self) -> Arc<VerifiedPrefix> {
        Arc::clone(&self.current)
    }

    /// Cold-open finalization only, outside State and before owner exposure.
    /// The caller has admitted CURRENT, every selected row, strict snapshot
    /// descriptor and the complete WAL suffix. Recheck every selected byte on
    /// the same descriptor before touching an unselected tail. A failed or
    /// cancelled repair fences all views and cannot be retried in this owner.
    pub(crate) fn repair_unselected_tail(
        &mut self,
        path: &Path,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let source = Arc::clone(&self.current.source);
        let mut fence = FailureFence::new(&source.failed);
        let before = self.opened.take().ok_or_else(invalid)?;
        let selected = self.current.identity;
        check()?;
        let named = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        if MetadataIdentity::read(&named.metadata()?)? != before
            || source.metadata()? != before
            || source.admitted_length.load(Ordering::Acquire) != selected.length
        {
            return Err(invalid());
        }
        let _memory = VerificationMemory::reserve(selected.block_bytes)?;
        let mut bytes = buffer(selected.block_bytes)?;
        let mut hasher = Sha256::new();
        for index in 0..selected.blocks(source.maximum)? {
            check()?;
            source
                .file
                .read_exact_at(&mut bytes, index as u64 * selected.block_bytes as u64)?;
            if <[u8; 32]>::from(Sha256::digest(&*bytes)) != source.digest(index)? {
                return Err(invalid());
            }
            hasher.update(&*bytes);
        }
        check()?;
        if <[u8; 32]>::from(hasher.finalize()) != selected.digest || source.metadata()? != before {
            return Err(invalid());
        }
        if before.length != selected.length {
            source.file.set_len(selected.length)?;
        }
        // An interrupted earlier repair may have completed truncate and then
        // failed its sync. Equal extent still needs durable stabilization.
        source.file.sync_all()?;
        let synced = source.metadata()?;
        if synced.length != selected.length {
            return Err(invalid());
        }
        check()?;
        if source.metadata()? != synced {
            return Err(invalid());
        }
        // A namespace replacement cannot make the next owner silently open
        // different bytes from the descriptor this owner has just admitted.
        let named = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        if MetadataIdentity::read(&named.metadata()?)? != synced || source.metadata()? != synced {
            return Err(invalid());
        }
        fence.accept();
        Ok(())
    }

    /// Write exactly one complete encoded transaction, append canonical zero
    /// padding, sync, and decode its verified readback to exact EOF. The format
    /// validator must compare every decoded field to its captured expectation;
    /// the primitive deliberately cannot manufacture a semantic certificate.
    /// The transaction's checkpoint advances even when its operation sequence
    /// is unchanged.
    pub(crate) fn append(
        &mut self,
        predecessor: &Arc<VerifiedPrefix>,
        transaction: AppendTransaction,
        mut check: impl FnMut() -> io::Result<()>,
        encode: impl FnOnce(&mut dyn Write) -> io::Result<()>,
        validate: impl FnOnce(&mut dyn Read) -> io::Result<()>,
    ) -> io::Result<Arc<VerifiedPrefix>> {
        let AppendTransaction {
            checkpoint_epoch,
            operation_sequence,
            frontiers,
            payload_bytes,
        } = transaction;
        let source = Arc::clone(&self.current.source);
        let mut fence = FailureFence::new(&source.failed);
        let previous = self.current.identity;
        if !Arc::ptr_eq(predecessor, &self.current)
            || checkpoint_epoch == u64::MAX
            || previous.checkpoint_epoch.checked_add(1) != Some(checkpoint_epoch)
            || operation_sequence < previous.operation_sequence
            || payload_bytes == 0
        {
            return Err(invalid());
        }
        let payload_end = previous
            .length
            .checked_add(payload_bytes)
            .ok_or_else(invalid)?;
        let length = payload_end
            .checked_add(previous.block_bytes as u64 - 1)
            .map(|end| end / previous.block_bytes as u64 * previous.block_bytes as u64)
            .ok_or_else(invalid)?;
        let mut next = PrefixIdentity {
            checkpoint_epoch,
            operation_sequence,
            frontiers,
            length,
            ..previous
        };
        let total = next.blocks(source.maximum)?;
        let first = previous.blocks(source.maximum)?;
        let count = total
            .checked_sub(first)
            .filter(|count| *count != 0)
            .ok_or_else(invalid)?;
        let page_count = total.div_ceil(PAGE_BLOCKS) - first.div_ceil(PAGE_BLOCKS);
        // All fallible reservations, page allocations and view allocation
        // precede the first write. Both encoding and readback buffers count.
        let scratch_bytes = count
            .checked_mul(32)
            .and_then(|n| {
                n.checked_add(page_count.checked_mul(size_of::<(usize, Box<DigestPage>)>())?)
            })
            .and_then(|n| n.checked_add(previous.block_bytes.checked_mul(2)?))
            .ok_or_else(invalid)?;
        let _scratch = VerificationMemory::reserve(scratch_bytes)?;
        let mut digests = Vec::new();
        digests.try_reserve_exact(count).map_err(|_| invalid())?;
        let mut pages = Vec::new();
        pages.try_reserve_exact(page_count).map_err(|_| invalid())?;
        for page in first.div_ceil(PAGE_BLOCKS)..total.div_ceil(PAGE_BLOCKS) {
            check()?;
            if source.pages[page].get().is_some() {
                return Err(invalid());
            }
            pages.push((page, DigestPage::allocate()?));
        }
        let view_memory = VerificationMemory::reserve(size_of::<VerifiedPrefix>() + ARC_HEADER)?;
        let mut view = Arc::new(VerifiedPrefix {
            source: Arc::clone(&source),
            identity: next,
            _memory: view_memory,
        });
        let write_buffer = buffer(previous.block_bytes)?;
        let read_buffer = buffer(previous.block_bytes)?;
        check()?;
        if source.metadata()?.length != previous.length {
            return Err(invalid());
        }
        let encoded_hasher = {
            let mut writer = ExtentWriter {
                file: &source.file,
                start: previous.length,
                payload_bytes,
                written: 0,
                block_written: 0,
                buffer: write_buffer,
                digests: &mut digests,
                hasher: self.hasher.clone(),
                check: &mut check,
            };
            encode(&mut writer)?;
            writer.finish()?
        };
        if digests.len() != count || source.metadata()?.length != length {
            return Err(invalid());
        }
        check()?;
        source.file.sync_all()?;
        check()?;
        let synced = source.metadata()?;
        if synced.length != length {
            return Err(invalid());
        }
        let mut reader = ExtentReader {
            source: &source,
            start: previous.length,
            payload_bytes,
            position: 0,
            loaded: 0,
            buffer: read_buffer,
            digests: &digests,
            hasher: self.hasher.clone(),
            check: &mut check,
        };
        validate(&mut reader)?;
        if reader.position != payload_bytes || reader.loaded != count {
            return Err(invalid());
        }
        let readback_digest: [u8; 32] = reader.hasher.clone().finalize().into();
        next.digest = encoded_hasher.clone().finalize().into();
        if readback_digest != next.digest {
            return Err(invalid());
        }
        drop(reader);
        check()?;
        if source.metadata()? != synced {
            return Err(invalid());
        }
        // No old digest changes. Unpublished new slots are inaccessible to
        // old fixed-length views. Any panic/error fences all views, and a cold
        // reopen must re-admit the selected prefix before classifying the tail.
        for (page, contents) in pages {
            source.pages[page].set(contents).map_err(|_| invalid())?;
        }
        for (offset, digest) in digests.into_iter().enumerate() {
            if offset % PAGE_BLOCKS == 0 {
                check()?;
            }
            source.fill(first + offset, digest)?;
        }
        if source.metadata()? != synced {
            return Err(invalid());
        }
        Arc::get_mut(&mut view).ok_or_else(invalid)?.identity = next;
        source.admitted_length.store(length, Ordering::Release);
        self.current = Arc::clone(&view);
        self.hasher = encoded_hasher;
        self.opened = None;
        fence.accept();
        Ok(view)
    }
}

struct ExtentWriter<'a> {
    file: &'a File,
    start: u64,
    payload_bytes: u64,
    written: u64,
    block_written: usize,
    buffer: Zeroizing<Vec<u8>>,
    digests: &'a mut Vec<[u8; 32]>,
    hasher: Sha256,
    check: &'a mut dyn FnMut() -> io::Result<()>,
}
impl ExtentWriter<'_> {
    fn block(&mut self) -> io::Result<()> {
        (self.check)()?;
        let offset = self
            .start
            .checked_add(self.digests.len() as u64 * self.buffer.len() as u64)
            .ok_or_else(invalid)?;
        self.file.write_all_at(&self.buffer, offset)?;
        self.digests.push(Sha256::digest(&*self.buffer).into());
        self.hasher.update(&*self.buffer);
        self.block_written = 0;
        Ok(())
    }
    fn finish(mut self) -> io::Result<Sha256> {
        if self.written != self.payload_bytes {
            return Err(invalid());
        }
        if self.block_written != 0 {
            self.buffer[self.block_written..].fill(0);
            self.block()?;
        }
        Ok(self.hasher)
    }
}
impl Write for ExtentWriter<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        if self.written >= self.payload_bytes {
            return Err(invalid());
        }
        let count = usize::try_from(self.payload_bytes - self.written)
            .unwrap_or(usize::MAX)
            .min(input.len())
            .min(self.buffer.len() - self.block_written);
        self.buffer[self.block_written..self.block_written + count]
            .copy_from_slice(&input[..count]);
        self.block_written += count;
        self.written += count as u64;
        if self.block_written == self.buffer.len() {
            self.block()?;
        }
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Sequential validation exposes exactly the transaction payload. Each whole
// block is checked before any payload bytes escape, including canonical zero
// padding in its final block. A decoder that stops early cannot admit a view.
struct ExtentReader<'a> {
    source: &'a VerifiedAppendSource,
    start: u64,
    payload_bytes: u64,
    position: u64,
    loaded: usize,
    buffer: Zeroizing<Vec<u8>>,
    digests: &'a [[u8; 32]],
    hasher: Sha256,
    check: &'a mut dyn FnMut() -> io::Result<()>,
}
impl Read for ExtentReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.payload_bytes {
            return Ok(0);
        }
        let block_bytes = self.buffer.len();
        let index = usize::try_from(self.position / block_bytes as u64).map_err(|_| invalid())?;
        if index == self.loaded {
            (self.check)()?;
            self.source.metadata()?;
            self.source.file.read_exact_at(
                &mut self.buffer,
                self.start + index as u64 * block_bytes as u64,
            )?;
            let actual: [u8; 32] = Sha256::digest(&*self.buffer).into();
            if self.digests.get(index) != Some(&actual) {
                return Err(invalid());
            }
            let body = usize::try_from(
                (self.payload_bytes - index as u64 * block_bytes as u64).min(block_bytes as u64),
            )
            .map_err(|_| invalid())?;
            if self.buffer[body..].iter().any(|byte| *byte != 0) {
                return Err(invalid());
            }
            self.hasher.update(&*self.buffer);
            self.loaded += 1;
        }
        if self.loaded != index + 1 {
            return Err(invalid());
        }
        let inside = (self.position % block_bytes as u64) as usize;
        let count = usize::try_from(self.payload_bytes - self.position)
            .unwrap_or(usize::MAX)
            .min(output.len())
            .min(block_bytes - inside);
        output[..count].copy_from_slice(&self.buffer[inside..inside + count]);
        self.position += count as u64;
        Ok(count)
    }
}

#[cfg(test)]
mod tests;
