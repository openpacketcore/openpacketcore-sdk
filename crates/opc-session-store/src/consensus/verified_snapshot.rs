//! Safe, bounded verified reads from a mutable filesystem inode.
//!
//! The retained digest index is process-owned authority for one byte image.
//! A changed file can cause an error, but can never change the bytes returned
//! for that image. No whole-snapshot buffer or on-disk proof sidecar is used.

use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use opc_sqlite_file_control_sys::{RegisteredSnapshot, VerifiedSnapshotSource};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const MIN_BLOCK_BYTES: usize = 64 * 1024;
const MAX_BLOCK_BYTES: usize = 2 * 1024 * 1024;
const MAX_INDEX_BYTES: usize = 16 * 1024 * 1024;
const DIGEST_BYTES: usize = 32;
const MAX_BLOCKS: usize = MAX_INDEX_BYTES / DIGEST_BYTES;
const PROCESS_VERIFICATION_BYTES: usize = 128 * 1024 * 1024;
static VERIFICATION_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Reservation shared across all retained images, their cache replacement
/// buffers, and asynchronous transport reads. Exhaustion fails closed before
/// allocating or spawning work; dropping the owner returns the reservation.
pub(crate) struct VerificationMemory {
    bytes: usize,
    counter: &'static AtomicUsize,
}

impl VerificationMemory {
    pub(crate) fn reserve(bytes: usize) -> io::Result<Self> {
        Self::reserve_from(&VERIFICATION_BYTES, bytes, PROCESS_VERIFICATION_BYTES)
    }

    fn reserve_from(counter: &'static AtomicUsize, bytes: usize, limit: usize) -> io::Result<Self> {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|total| *total <= limit)
            })
            .map_err(|_| io::Error::other("portable snapshot verification memory limit reached"))?;
        Ok(Self { bytes, counter })
    }
}

impl Drop for VerificationMemory {
    fn drop(&mut self) {
        self.counter.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "portable snapshot integrity check failed",
    )
}

fn block_size(length: u64) -> io::Result<usize> {
    let mut bytes = MIN_BLOCK_BYTES;
    while length.div_ceil(bytes as u64) > MAX_BLOCKS as u64 {
        bytes = bytes.checked_mul(2).ok_or_else(invalid)?;
        if bytes > MAX_BLOCK_BYTES {
            return Err(invalid());
        }
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Generation {
    device: u64,
    inode: u64,
    length: u64,
    change_seconds: i64,
    change_nanoseconds: i64,
}

impl Generation {
    fn read(metadata: &Metadata) -> io::Result<Self> {
        if !metadata.is_file() || metadata.nlink() == 0 {
            return Err(invalid());
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            change_seconds: metadata.ctime(),
            change_nanoseconds: metadata.ctime_nsec(),
        })
    }

    fn same_object_and_length(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode && self.length == other.length
    }
}

struct CachedBlock {
    generation: Generation,
    index: usize,
    bytes: Zeroizing<Vec<u8>>,
}

pub(crate) struct VerifiedFile {
    file: File,
    generation: Generation,
    block_bytes: usize,
    blocks: Box<[[u8; DIGEST_BYTES]]>,
    digest: [u8; DIGEST_BYTES],
    // One verified owned block, shared by descriptor clones. Ctime is only a
    // cache invalidation hint: every newly loaded block is hashed regardless.
    cache: Mutex<Option<CachedBlock>>,
    _memory: VerificationMemory,
}

impl VerifiedFile {
    pub(crate) fn capture(file: File, maximum: u64) -> io::Result<Arc<Self>> {
        Self::capture_checked(file, maximum, || Ok(()))
    }

    fn capture_checked(
        file: File,
        maximum: u64,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Arc<Self>> {
        check()?;
        let before = Generation::read(&file.metadata()?)?;
        if before.length == 0 || before.length > maximum {
            return Err(invalid());
        }
        let block_bytes = block_size(before.length)?;
        let count =
            usize::try_from(before.length.div_ceil(block_bytes as u64)).map_err(|_| invalid())?;
        if count > MAX_BLOCKS {
            return Err(invalid());
        }
        let memory_bytes = count
            .checked_mul(DIGEST_BYTES)
            .and_then(|index| index.checked_add(block_bytes.checked_mul(2)?))
            .ok_or_else(invalid)?;
        let memory = VerificationMemory::reserve(memory_bytes)?;
        let mut blocks = Vec::new();
        blocks.try_reserve_exact(count).map_err(|_| invalid())?;
        let mut buffer = Zeroizing::new(vec![0; block_bytes]);
        let mut hasher = Sha256::new();
        let mut offset = 0;
        while offset < before.length {
            check()?;
            let bytes = usize::try_from((before.length - offset).min(block_bytes as u64))
                .map_err(|_| invalid())?;
            file.read_exact_at(&mut buffer[..bytes], offset)?;
            hasher.update(&buffer[..bytes]);
            blocks.push(Sha256::digest(&buffer[..bytes]).into());
            offset = offset.checked_add(bytes as u64).ok_or_else(invalid)?;
        }
        check()?;
        if Generation::read(&file.metadata()?)? != before || blocks.len() != count {
            return Err(invalid());
        }
        Ok(Arc::new(Self {
            file,
            generation: before,
            block_bytes,
            blocks: blocks.into_boxed_slice(),
            digest: hasher.finalize().into(),
            cache: Mutex::new(None),
            _memory: memory,
        }))
    }

    pub(crate) fn length(&self) -> u64 {
        self.generation.length
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        let current = Generation::read(&self.file.metadata()?)?;
        if !self.generation.same_object_and_length(current) {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        let end = offset
            .checked_add(output.len() as u64)
            .ok_or_else(invalid)?;
        if end > self.length() {
            return Err(invalid());
        }
        self.validate()?;
        let mut position = offset;
        let mut output_offset = 0;
        let mut cache = self.cache.lock().map_err(|_| invalid())?;
        while position < end {
            let generation = Generation::read(&self.file.metadata()?)?;
            if !self.generation.same_object_and_length(generation) {
                return Err(invalid());
            }
            let index =
                usize::try_from(position / self.block_bytes as u64).map_err(|_| invalid())?;
            let block_start = (index as u64)
                .checked_mul(self.block_bytes as u64)
                .ok_or_else(invalid)?;
            let in_block = usize::try_from(position - block_start).map_err(|_| invalid())?;
            if cache
                .as_ref()
                .is_none_or(|cached| cached.index != index || cached.generation != generation)
            {
                let bytes =
                    usize::try_from((self.length() - block_start).min(self.block_bytes as u64))
                        .map_err(|_| invalid())?;
                let mut buffer = Zeroizing::new(vec![0; bytes]);
                self.file.read_exact_at(&mut buffer, block_start)?;
                let actual: [u8; 32] = Sha256::digest(&*buffer).into();
                if self.blocks.get(index) != Some(&actual) {
                    return Err(invalid());
                }
                *cache = Some(CachedBlock {
                    generation,
                    index,
                    bytes: buffer,
                });
            }
            let cached = cache.as_ref().ok_or_else(invalid)?;
            let bytes = cached
                .bytes
                .len()
                .saturating_sub(in_block)
                .min(output.len() - output_offset);
            if bytes == 0 {
                return Err(invalid());
            }
            output[output_offset..output_offset + bytes]
                .copy_from_slice(&cached.bytes[in_block..in_block + bytes]);
            position += bytes as u64;
            output_offset += bytes;
        }
        Ok(())
    }

    pub(crate) fn reader(self: &Arc<Self>) -> VerifiedReader {
        VerifiedReader {
            source: Arc::clone(self),
            position: 0,
        }
    }
}

impl VerifiedSnapshotSource for VerifiedFile {
    fn len(&self) -> u64 {
        self.length()
    }

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        VerifiedFile::read_exact_at(self, offset, output)
    }

    fn validate(&self) -> io::Result<()> {
        VerifiedFile::validate(self)
    }

    fn duplicate_descriptor(&self) -> io::Result<File> {
        self.file.try_clone()
    }
}

pub(crate) struct PortableSnapshot {
    pub(crate) source: Arc<VerifiedFile>,
    registration: RegisteredSnapshot,
}

impl PortableSnapshot {
    pub(crate) fn capture(file: File, maximum: u64) -> io::Result<Arc<Self>> {
        let source = VerifiedFile::capture(file, maximum)?;
        Self::register(source)
    }

    pub(crate) fn capture_checked(
        file: File,
        maximum: u64,
        check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Arc<Self>> {
        Self::register(VerifiedFile::capture_checked(file, maximum, check)?)
    }

    fn register(source: Arc<VerifiedFile>) -> io::Result<Arc<Self>> {
        let registration =
            RegisteredSnapshot::new(Arc::clone(&source) as Arc<dyn VerifiedSnapshotSource>)
                .map_err(|_| io::Error::other("portable snapshot read registration unavailable"))?;
        Ok(Arc::new(Self {
            source,
            registration,
        }))
    }

    pub(crate) fn sqlite_uri(&self) -> String {
        self.registration.uri()
    }
}

pub(crate) struct VerifiedReader {
    source: Arc<VerifiedFile>,
    position: u64,
}

impl Read for VerifiedReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let bytes = usize::try_from(self.source.length().saturating_sub(self.position))
            .unwrap_or(usize::MAX)
            .min(output.len());
        if bytes == 0 {
            self.source.validate()?;
            return Ok(0);
        }
        self.source
            .read_exact_at(self.position, &mut output[..bytes])?;
        self.position += bytes as u64;
        Ok(bytes)
    }
}

impl Seek for VerifiedReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.position = match position {
            SeekFrom::Start(position) => Some(position),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
            SeekFrom::End(delta) => self.source.length().checked_add_signed(delta),
        }
        .ok_or_else(invalid)?;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn verification_reservations_are_bounded_and_released() {
        static USED: AtomicUsize = AtomicUsize::new(0);
        let first = VerificationMemory::reserve_from(&USED, 70, 100).expect("first reservation");
        assert!(VerificationMemory::reserve_from(&USED, 31, 100).is_err());
        assert!(VerificationMemory::reserve_from(&USED, usize::MAX, 100).is_err());
        let second = VerificationMemory::reserve_from(&USED, 30, 100).expect("exact bound");
        assert_eq!(100, USED.load(Ordering::Acquire));
        drop(first);
        assert_eq!(30, USED.load(Ordering::Acquire));
        drop(second);
        assert_eq!(0, USED.load(Ordering::Acquire));
    }

    #[test]
    fn portable_snapshot_representative_index_and_read_measurement() {
        fn consume(mut reader: impl Read) -> (u64, [u8; 32]) {
            let mut buffer = [0_u8; MIN_BLOCK_BYTES];
            let mut bytes = 0;
            let mut digest = Sha256::new();
            loop {
                let read = reader.read(&mut buffer).expect("measurement read");
                if read == 0 {
                    return (bytes, digest.finalize().into());
                }
                digest.update(&buffer[..read]);
                bytes += read as u64;
            }
        }

        let mut artifact = tempfile::NamedTempFile::new().expect("measurement fixture");
        let block = vec![0x51_u8; MIN_BLOCK_BYTES];
        for _ in 0..512 {
            artifact.write_all(&block).expect("write 32 MiB fixture");
        }
        artifact.flush().expect("flush fixture");
        let started = std::time::Instant::now();
        let source =
            VerifiedFile::capture(artifact.reopen().expect("snapshot descriptor"), u64::MAX)
                .expect("bounded index capture");
        let index_time = started.elapsed();
        let started = std::time::Instant::now();
        let (verified_bytes, verified_digest) = consume(source.reader());
        let verified_time = started.elapsed();
        let started = std::time::Instant::now();
        let (raw_bytes, raw_digest) = consume(artifact.reopen().expect("baseline descriptor"));
        let raw_time = started.elapsed();
        assert_eq!(32 * 1024 * 1024, verified_bytes);
        assert_eq!(raw_bytes, verified_bytes);
        assert_eq!(raw_digest, verified_digest);
        // Observational only: timings are not a hardware-dependent pass/fail
        // threshold or a production throughput/HA claim.
        eprintln!("portable snapshot measurement: bytes={verified_bytes} index={index_time:?} verified_read={verified_time:?} raw_read={raw_time:?}");
    }

    #[test]
    fn indexing_checks_cancellation_between_bounded_blocks() {
        let mut artifact = tempfile::NamedTempFile::new().expect("indexing fixture");
        artifact
            .write_all(&vec![0x51; MIN_BLOCK_BYTES * 3])
            .expect("write indexing fixture");
        let mut checks = 0;
        let result =
            VerifiedFile::capture_checked(artifact.reopen().expect("descriptor"), u64::MAX, || {
                checks += 1;
                if checks >= 3 {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "injected inspection deadline",
                    ))
                } else {
                    Ok(())
                }
            });
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut));
        assert_eq!(
            3, checks,
            "indexing stops without scanning the remaining blocks"
        );
    }

    #[test]
    fn sqlite_rejects_an_unread_page_changed_after_attach_even_with_mmap_requested() {
        let directory = tempfile::tempdir().expect("SQLite fixture directory");
        let path = directory.path().join("snapshot.sqlite");
        {
            let writer = rusqlite::Connection::open(&path).expect("create fixture");
            writer.execute_batch("PRAGMA page_size = 4096; CREATE TABLE state(id INTEGER PRIMARY KEY, payload BLOB);")
                .expect("fixture schema");
            for id in 1..=128 {
                writer
                    .execute(
                        "INSERT INTO state VALUES (?1, ?2)",
                        rusqlite::params![id, vec![0x51_u8; 8192]],
                    )
                    .expect("fixture overflow pages");
            }
        }
        let portable =
            PortableSnapshot::capture(File::open(&path).expect("open snapshot"), u64::MAX)
                .expect("capture image");
        let reader = rusqlite::Connection::open_in_memory().expect("reader");
        reader
            .execute("ATTACH DATABASE ?1 AS snapshot", [portable.sqlite_uri()])
            .expect("attach image");
        reader
            .execute_batch(
                "PRAGMA snapshot.mmap_size = 1073741824; PRAGMA snapshot.cache_size = 1;",
            )
            .expect("request mmap and small page cache");
        let first: Vec<u8> = reader
            .query_row(
                "SELECT payload FROM snapshot.state WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .expect("read initial row before corruption");
        assert_eq!(vec![0x51; 8192], first);
        let source_length = portable.source.length();
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("same-inode writer");
        // The last overflow page belongs to the last inserted row and has
        // not been consumed by SQLite's first-row lookup.
        writer
            .write_all_at(&[0x7e], source_length - 16)
            .expect("change unread overflow page");
        writer.sync_all().expect("persist changed page");
        assert!(
            reader
                .query_row(
                    "SELECT payload FROM snapshot.state WHERE id = 128",
                    [],
                    |row| row.get::<_, Vec<u8>>(0)
                )
                .is_err(),
            "an already-attached reader cannot consume an unverified changed page"
        );
    }

    #[test]
    fn digest_index_is_bounded_at_the_existing_physical_ceiling() {
        let maximum = super::super::snapshot::SNAPSHOT_ENVELOPE_MAX_BYTES;
        let block_bytes = block_size(maximum).expect("maximum snapshot has a bounded block size");
        assert_eq!(MAX_BLOCK_BYTES, block_bytes);
        assert!(
            maximum.div_ceil(block_bytes as u64) * DIGEST_BYTES as u64 <= MAX_INDEX_BYTES as u64
        );
        assert_eq!(
            MIN_BLOCK_BYTES,
            block_size(1024 * 1024).expect("small snapshot block size")
        );
        assert!(block_size(MAX_BLOCK_BYTES as u64 * MAX_BLOCKS as u64 + 1).is_err());
    }

    #[test]
    fn verified_reads_reject_post_capture_changes_and_truncation() {
        let mut artifact = tempfile::NamedTempFile::new().expect("snapshot fixture");
        artifact
            .write_all(&vec![0x51; MIN_BLOCK_BYTES * 2 + 7])
            .expect("write snapshot fixture");
        artifact.flush().expect("flush snapshot fixture");
        let source = VerifiedFile::capture(artifact.reopen().expect("read descriptor"), u64::MAX)
            .expect("capture verified generation");
        let mut actual = vec![0; MIN_BLOCK_BYTES + 4];
        source
            .read_exact_at(5, &mut actual)
            .expect("read across block boundary");
        assert!(actual.iter().all(|byte| *byte == 0x51));
        artifact
            .as_file()
            .write_all_at(&[0x7e], (MIN_BLOCK_BYTES * 2) as u64)
            .expect("mutate uncached source block");
        assert!(source
            .read_exact_at((MIN_BLOCK_BYTES * 2) as u64, &mut [0; 1])
            .is_err());
        artifact.as_file().set_len(1).expect("truncate source");
        assert!(source.read_exact_at(0, &mut [0; 1]).is_err());
    }

    #[test]
    fn sqlite_consumes_verified_bytes_and_keeps_descriptor_identity() {
        let directory = tempfile::tempdir().expect("SQLite fixture directory");
        let path = directory.path().join("snapshot.sqlite");
        {
            let writer = rusqlite::Connection::open(&path).expect("create fixture");
            writer
                .execute_batch("CREATE TABLE state(value INTEGER); INSERT INTO state VALUES (41);")
                .expect("write fixture state");
        }
        let portable = PortableSnapshot::capture(File::open(&path).expect("open source"), u64::MAX)
            .expect("capture SQLite snapshot");
        let open = || {
            rusqlite::Connection::open_with_flags(
                portable.sqlite_uri(),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
            )
        };
        let reader = open().expect("open verified SQLite reader");
        assert_eq!(
            41,
            reader
                .query_row("SELECT value FROM state", [], |row| row.get::<_, i64>(0))
                .expect("query verified state")
        );
        assert!(reader.execute("UPDATE state SET value = 42", []).is_err());
        let descriptor = opc_sqlite_file_control_sys::main_file_descriptor(&reader)
            .expect("retain verified descriptor identity");
        assert_eq!(
            descriptor.metadata().expect("descriptor metadata").ino(),
            File::open(&path)
                .expect("source descriptor")
                .metadata()
                .expect("source metadata")
                .ino()
        );
        drop(reader);
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("external writer");
        writer
            .write_all_at(&[0; 16], 0)
            .expect("corrupt source after validation");
        assert!(
            open().is_err(),
            "a new SQLite handle must not read changed source bytes"
        );
    }
}
