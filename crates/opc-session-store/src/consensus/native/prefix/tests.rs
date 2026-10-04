use super::*;
use std::cell::Cell;

struct Fixture {
    directory: tempfile::TempDir,
    path: std::path::PathBuf,
    file: File,
    identity: PrefixIdentity,
}

impl Fixture {
    fn new(blocks: usize) -> Self {
        let directory = tempfile::tempdir().expect("prefix directory");
        let path = directory.path().join("generation.native");
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .expect("prefix fixture");
        let bytes = vec![0x51; MIN_BLOCK];
        let mut hash = Sha256::new();
        for _ in 0..blocks {
            file.write_all(&bytes).expect("base block");
            hash.update(&bytes);
        }
        file.sync_all().expect("base sync");
        let identity = PrefixIdentity {
            binding: [1; 32],
            file_epoch: 8,
            checkpoint_epoch: 19,
            operation_sequence: 41,
            frontiers: [2; 32],
            length: (MIN_BLOCK * blocks) as u64,
            block_bytes: MIN_BLOCK,
            digest: hash.finalize().into(),
        };
        Self {
            directory,
            path,
            file,
            identity,
        }
    }

    fn open(&self) -> VerifiedAppendOwner {
        VerifiedAppendOwner::open(
            &self.path,
            self.identity,
            64 * 1024 * 1024,
            || Ok(()),
            |reader| check_bytes(reader, self.identity.length, 0x51),
        )
        .expect("full selected-prefix admission")
    }
}

fn check_bytes(reader: &mut (impl Read + ?Sized), mut count: u64, byte: u8) -> io::Result<()> {
    let mut buffer = [0; 8192];
    while count != 0 {
        let size = count.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..size])?;
        if buffer[..size].iter().any(|actual| *actual != byte) {
            return Err(invalid());
        }
        count -= size as u64;
    }
    Ok(())
}

fn append(owner: &mut VerifiedAppendOwner, bytes: &[u8]) -> io::Result<Arc<VerifiedPrefix>> {
    let previous = owner.current();
    owner.append(
        &previous,
        crate::consensus::native::prefix::AppendTransaction {
            checkpoint_epoch: previous.identity.checkpoint_epoch + 1,
            operation_sequence: previous.identity.operation_sequence,
            frontiers: [3; 32],
            payload_bytes: bytes.len() as u64,
        },
        || Ok(()),
        |writer| writer.write_all(bytes),
        |reader| {
            let mut position = 0;
            let mut buffer = [0; 8192];
            while position < bytes.len() {
                let count = (bytes.len() - position).min(buffer.len());
                reader.read_exact(&mut buffer[..count])?;
                if buffer[..count] != bytes[position..position + count] {
                    return Err(invalid());
                }
                position += count;
            }
            if reader.read(&mut [0])? != 0 {
                return Err(invalid());
            }
            Ok(())
        },
    )
}

#[test]
fn native_prefix_two_active_blocks_reuse_authenticated_bytes_without_allocations() {
    let fixture = Fixture::new(1);
    let mut owner = fixture.open();
    let view = append(&mut owner, &vec![0x62; MIN_BLOCK]).unwrap();
    let mut actual = vec![0; MIN_BLOCK];
    // Visit the working set twice before measuring. A one-way cold scan
    // need not allocate the second buffer reserved for alternating reads.
    for (offset, expected) in [
        (0, 0x51),
        (MIN_BLOCK as u64, 0x62),
        (0, 0x51),
        (MIN_BLOCK as u64, 0x62),
    ] {
        view.read_exact_at(offset, &mut actual).unwrap();
        assert!(actual.iter().all(|byte| *byte == expected));
    }
    let before = view.blocks_read();
    let allocations = allocation_counter::measure(|| {
        for index in 0..64 {
            let (offset, expected) = if index % 2 == 0 {
                (0, 0x51)
            } else {
                (MIN_BLOCK as u64, 0x62)
            };
            view.read_exact_at(offset, &mut actual).unwrap();
            assert!(actual.iter().all(|byte| *byte == expected));
        }
    });
    assert_eq!(
        view.blocks_read() - before,
        0,
        "alternating two admitted blocks must not verify the same file bytes repeatedly",
    );
    assert_eq!(allocations.bytes_total, 0);
    assert!(!view.is_failed());
}

#[test]
fn native_prefix_cache_misses_bound_allocations_and_preserve_every_verified_byte() {
    let fixture = Fixture::new(1);
    let mut owner = fixture.open();
    append(&mut owner, &vec![0x62; MIN_BLOCK]).unwrap();
    let view = append(&mut owner, &vec![0x73; MIN_BLOCK]).unwrap();
    let mut actual = vec![0; MIN_BLOCK];
    for (offset, expected) in [(MIN_BLOCK as u64, 0x62), (2 * MIN_BLOCK as u64, 0x73)] {
        view.read_exact_at(offset, &mut actual).unwrap();
        assert!(actual.iter().all(|byte| *byte == expected));
    }
    let before = view.blocks_read();
    let started = std::time::Instant::now();
    let allocations = allocation_counter::measure(|| {
        for index in 0..64 {
            // Three blocks still force a real eviction on every read with
            // two cache slots. Keep the original 64-miss allocation bound.
            let (offset, expected) = match index % 3 {
                0 => (0, 0x51),
                1 => (MIN_BLOCK as u64, 0x62),
                _ => (2 * MIN_BLOCK as u64, 0x73),
            };
            view.read_exact_at(offset, &mut actual).unwrap();
            assert!(actual.iter().all(|byte| *byte == expected));
        }
    });
    assert_eq!(view.blocks_read() - before, 64);
    assert!(!view.is_failed());
    eprintln!(
        "native_prefix_cache_misses reads=64 bytes_total={} count_total={} elapsed_us={}",
        allocations.bytes_total,
        allocations.count_total,
        started.elapsed().as_micros(),
    );
    assert!(
        allocations.bytes_total <= 2 * MIN_BLOCK as u64,
        "authenticated cache misses allocate a fresh block for every read",
    );
}

#[test]
fn native_prefix_same_sequence_checkpoints_keep_fixed_views_and_cold_exact_bytes() {
    let fixture = Fixture::new(2);
    let mut owner = fixture.open();
    let first = owner.current();
    let second =
        append(&mut owner, &vec![0x62; MIN_BLOCK + 13]).expect("first same-sequence checkpoint");
    let third = append(&mut owner, &[0x73; 7]).expect("second same-sequence checkpoint");
    assert_eq!(8, third.identity().file_epoch);
    assert_eq!(21, third.identity().checkpoint_epoch);
    assert_eq!(41, third.identity().operation_sequence);
    assert_eq!(5 * MIN_BLOCK as u64, third.identity().length);
    assert!(Arc::ptr_eq(&first.source, &second.source));
    assert!(Arc::ptr_eq(&second.source, &third.source));
    assert_eq!(
        1,
        first
            .source
            .pages
            .iter()
            .filter(|page| page.get().is_some())
            .count()
    );
    check_bytes(&mut first.reader(), first.identity.length, 0x51)
        .expect("old prefix survives append");
    assert!(first
        .read_exact_at(first.identity.length, &mut [0])
        .is_err());
    assert!(
        !first.is_failed(),
        "a caller range error is not disk corruption"
    );
    first
        .read_exact_at(first.identity.length, &mut [])
        .expect("fixed EOF");
    let mut reader = third.reader();
    check_bytes(&mut reader, 2 * MIN_BLOCK as u64, 0x51).expect("base");
    check_bytes(&mut reader, MIN_BLOCK as u64 + 13, 0x62).expect("first payload");
    check_bytes(&mut reader, MIN_BLOCK as u64 - 13, 0).expect("canonical first padding");
    check_bytes(&mut reader, 7, 0x73).expect("second payload");
    check_bytes(&mut reader, MIN_BLOCK as u64 - 7, 0).expect("canonical second padding");
    assert_eq!(0, reader.read(&mut [0]).expect("exact final EOF"));
    let actual = std::fs::read(&fixture.path).expect("independent raw bytes");
    assert_eq!(
        third.identity.digest,
        <[u8; 32]>::from(Sha256::digest(&actual))
    );
    let reopened = VerifiedAppendOwner::open(
        &fixture.path,
        third.identity,
        64 * 1024 * 1024,
        || Ok(()),
        |reader| {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes)?;
            if bytes != actual {
                return Err(invalid());
            }
            Ok(())
        },
    )
    .expect("complete cold comparison and semantic read");
    assert_eq!(third.identity(), reopened.current().identity());
}

#[test]
fn native_prefix_digest_pages_are_shared_write_once_across_page_boundary() {
    let fixture = Fixture::new(PAGE_BLOCKS - 1);
    let mut owner = fixture.open();
    let first = owner.current();
    let old_digest = first
        .source
        .digest(PAGE_BLOCKS - 2)
        .expect("last old digest");
    let page_address = first.source.pages[0].get().expect("first page") as *const _;
    let retained: Vec<_> = (0..128).map(|_| Arc::clone(&first)).collect();
    let next = append(&mut owner, &vec![0x6a; 3 * MIN_BLOCK]).expect("cross digest page");
    assert_eq!(
        2,
        next.source
            .pages
            .iter()
            .filter(|page| page.get().is_some())
            .count()
    );
    assert_eq!(
        page_address,
        next.source.pages[0].get().expect("shared page") as *const _
    );
    assert_eq!(
        old_digest,
        next.source
            .digest(PAGE_BLOCKS - 2)
            .expect("unchanged old digest")
    );
    assert!(
        next.source.fill(0, [0; 32]).is_err(),
        "an admitted slot cannot change"
    );
    assert!(retained.iter().all(|view| Arc::ptr_eq(&first, view)));
    drop(owner);
    drop(next);
    check_bytes(&mut first.reader(), first.identity.length, 0x51)
        .expect("old pin owns all generation storage");
}

#[test]
fn native_prefix_path_replacement_keeps_original_descriptor_and_symlink_rejects() {
    let fixture = Fixture::new(1);
    let mut owner = fixture.open();
    let original = fixture.directory.path().join("retained.native");
    std::fs::rename(&fixture.path, &original).expect("retain original inode");
    std::fs::write(&fixture.path, vec![0xa5; MIN_BLOCK]).expect("replace path");
    let next = append(&mut owner, &[0x67; 17]).expect("append original descriptor");
    assert_eq!(
        2 * MIN_BLOCK as u64,
        std::fs::metadata(&original).expect("old inode").len()
    );
    assert_eq!(
        vec![0xa5; MIN_BLOCK],
        std::fs::read(&fixture.path).expect("new path untouched")
    );
    check_bytes(&mut next.reader(), MIN_BLOCK as u64, 0x51).expect("read original inode");
    let symlink = fixture.directory.path().join("link.native");
    std::os::unix::fs::symlink(&original, &symlink).expect("symlink fixture");
    assert!(VerifiedAppendOwner::open(
        &symlink,
        next.identity,
        64 * 1024 * 1024,
        || Ok(()),
        |_| Ok(())
    )
    .is_err());
    std::fs::remove_file(&original).expect("unlink pinned inode");
    assert!(next.read_exact_at(0, &mut [0]).is_err());
    assert!(next.is_failed());
}

#[test]
fn native_prefix_mutation_truncation_and_appended_bytes_never_replace_admitted_values() {
    for corruption in 0..4 {
        let fixture = Fixture::new(2);
        let mut owner = fixture.open();
        let old = owner.current();
        let next = append(&mut owner, &vec![0x62; MIN_BLOCK + 7]).expect("new prefix");
        match corruption {
            0 => fixture
                .file
                .write_all_at(&[0xee], 0)
                .expect("change old block"),
            1 => fixture
                .file
                .write_all_at(&[0xee], old.identity.length)
                .expect("change new block"),
            2 => fixture
                .file
                .set_len(old.identity.length)
                .expect("truncate selected new prefix"),
            _ => fixture
                .file
                .write_all_at(&[0xee], next.identity.length - 1)
                .expect("change selected padding"),
        }
        fixture.file.sync_all().expect("persist corruption");
        let offset = match corruption {
            0 | 2 => 0,
            1 => old.identity.length,
            _ => next.identity.length - 1,
        };
        assert!(next.read_exact_at(offset, &mut [0]).is_err());
        assert!(old.is_failed(), "corruption fences every generation view");
        assert!(append(&mut owner, &[1]).is_err());
    }
}

#[test]
fn native_prefix_cached_bytes_remain_owned_after_mutation() {
    let fixture = Fixture::new(1);
    let owner = fixture.open();
    let view = owner.current();
    let mut byte = [0];
    view.read_exact_at(0, &mut byte).expect("prime cache");
    assert_eq!([0x51], byte);
    fixture
        .file
        .write_all_at(&[0xfe], 0)
        .expect("mutate cached block");
    fixture.file.sync_all().expect("sync mutation");
    // Ctime is only a hint, including on filesystems with coarse timestamps.
    // A retained owned block may still be the old exact image; changed bytes
    // must never appear through an admitted view.
    if view.read_exact_at(0, &mut byte).is_ok() {
        assert_eq!([0x51], byte);
    }
}

#[test]
fn native_prefix_wrong_identity_checkpoint_sequence_and_extent_reject_before_write() {
    for bad in 0..7 {
        let fixture = Fixture::new(1);
        let mut owner = fixture.open();
        let current = owner.current();
        let independent = fixture.open();
        let supplied = if bad == 0 {
            independent.current()
        } else {
            Arc::clone(&current)
        };
        let epoch = match bad {
            1 => current.identity.checkpoint_epoch,
            2 => u64::MAX,
            _ => current.identity.checkpoint_epoch + 1,
        };
        let sequence = if bad == 3 {
            current.identity.operation_sequence - 1
        } else {
            current.identity.operation_sequence
        };
        let payload = match bad {
            4 => 0,
            5 => u64::MAX,
            6 => 64 * 1024 * 1024,
            _ => 1,
        };
        let encoded = Cell::new(false);
        assert!(owner
            .append(
                &supplied,
                crate::consensus::native::prefix::AppendTransaction {
                    checkpoint_epoch: epoch,
                    operation_sequence: sequence,
                    frontiers: [3; 32],
                    payload_bytes: payload
                },
                || Ok(()),
                |_| {
                    encoded.set(true);
                    Ok(())
                },
                |_| Ok(()),
            )
            .is_err());
        assert!(!encoded.get());
        assert_eq!(
            fixture.identity.length,
            fixture.file.metadata().expect("unchanged extent").len()
        );
        assert!(current.is_failed());
    }
}

#[test]
fn native_prefix_short_overlong_semantically_invalid_or_unread_encoding_is_unpublished() {
    for bad in 0..4 {
        let fixture = Fixture::new(1);
        let mut owner = fixture.open();
        let old = owner.current();
        let bytes = [0x62; 17];
        let result = owner.append(
            &old,
            crate::consensus::native::prefix::AppendTransaction {
                checkpoint_epoch: 20,
                operation_sequence: 41,
                frontiers: [3; 32],
                payload_bytes: bytes.len() as u64,
            },
            || Ok(()),
            |writer| match bad {
                0 => writer.write_all(&bytes[..16]),
                1 => writer.write_all(&[0x62; 18]),
                _ => writer.write_all(&bytes),
            },
            |reader| match bad {
                2 => check_bytes(reader, bytes.len() as u64, 0xff),
                _ => Ok(()),
            },
        );
        assert!(result.is_err());
        assert_eq!(old.identity(), owner.current().identity());
        assert!(old.is_failed());
        // Opening the still-selected old prefix reads its exact bytes while
        // leaving any unselected physical tail in place for later admission.
        fixture.open();
    }
}

#[test]
fn native_prefix_readback_rejects_payload_and_padding_changed_on_same_inode() {
    for padding in [false, true] {
        let fixture = Fixture::new(1);
        let mut owner = fixture.open();
        let old = owner.current();
        assert!(owner
            .append(
                &old,
                crate::consensus::native::prefix::AppendTransaction {
                    checkpoint_epoch: 20,
                    operation_sequence: 41,
                    frontiers: [3; 32],
                    payload_bytes: 17
                },
                || Ok(()),
                |writer| { writer.write_all(&[0x62; 17]) },
                |reader| {
                    let offset = old.identity.length + if padding { 17 } else { 0 };
                    fixture.file.write_all_at(&[0x99], offset)?;
                    fixture.file.sync_all()?;
                    check_bytes(reader, 17, 0x62)
                },
            )
            .is_err());
        assert!(old.is_failed());
        assert_eq!(old.identity(), owner.current().identity());
    }
}

#[test]
fn native_prefix_failed_or_panicking_extension_fences_without_tail_repair() {
    for panic in [false, true] {
        let fixture = Fixture::new(1);
        let mut owner = fixture.open();
        let old = owner.current();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.append(
                &old,
                crate::consensus::native::prefix::AppendTransaction {
                    checkpoint_epoch: 20,
                    operation_sequence: 41,
                    frontiers: [3; 32],
                    payload_bytes: MIN_BLOCK as u64 + 1,
                },
                || Ok(()),
                |writer| {
                    writer.write_all(&vec![0x62; MIN_BLOCK])?;
                    if panic {
                        panic!("injected encoder unwind");
                    }
                    Err(io::Error::other("injected encoder failure"))
                },
                |_| Ok(()),
            )
        }));
        assert!(result.is_err() || result.is_ok_and(|inner| inner.is_err()));
        assert!(old.is_failed());
        assert_eq!(old.identity(), owner.current().identity());
        assert_eq!(
            2 * MIN_BLOCK as u64,
            fixture
                .file
                .metadata()
                .expect("unselected tail retained")
                .len()
        );
        let mut reopened = fixture.open();
        assert!(
            append(&mut reopened, &[1]).is_err(),
            "tail needs outer strict admission before repair"
        );
        assert_eq!(
            2 * MIN_BLOCK as u64,
            fixture.file.metadata().expect("no repair").len()
        );
    }
}

#[test]
fn native_prefix_reopen_checks_digest_canonical_bounds_full_decode_and_cancellation() {
    let fixture = Fixture::new(3);
    for bad in 0..8 {
        let mut identity = fixture.identity;
        match bad {
            0 => identity.digest[0] ^= 1,
            1 => identity.length -= 1,
            2 => identity.block_bytes = MIN_BLOCK / 2,
            3 => identity.block_bytes = MIN_BLOCK + 1,
            4 => identity.block_bytes = MAX_BLOCK * 2,
            5 => identity.length = (MAX_BLOCKS as u64 + 1) * MIN_BLOCK as u64,
            6 => identity.file_epoch = u64::MAX,
            _ => identity.checkpoint_epoch = u64::MAX,
        }
        let decode = Cell::new(false);
        assert!(VerifiedAppendOwner::open(
            &fixture.path,
            identity,
            u64::MAX,
            || Ok(()),
            |_| {
                decode.set(true);
                Ok(())
            }
        )
        .is_err());
        assert!(!decode.get());
    }
    assert!(
        VerifiedAppendOwner::open(
            &fixture.path,
            fixture.identity,
            fixture.identity.length,
            || Ok(()),
            |_| Ok(())
        )
        .is_err(),
        "unread selected bytes cannot be admitted"
    );
    let checks = Cell::new(0);
    assert!(VerifiedAppendOwner::open(
        &fixture.path,
        fixture.identity,
        fixture.identity.length,
        || {
            checks.set(checks.get() + 1);
            if checks.get() == 3 {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "injected cancellation",
                ))
            } else {
                Ok(())
            }
        },
        |_| Ok(())
    )
    .is_err());
    assert_eq!(3, checks.get(), "cancel between bounded blocks");
    assert_eq!(
        fixture.identity.length,
        fixture
            .file
            .metadata()
            .expect("cold admission never mutates")
            .len()
    );
}

#[test]
fn native_prefix_reservations_use_existing_process_limit_and_shared_view_ownership() {
    let fixture = Fixture::new(1);
    let owner = fixture.open();
    let first = owner.current();
    // This cannot succeed while a prefix reservation is alive. It checks the
    // existing shared counter without filling it or perturbing parallel tests.
    assert!(VerificationMemory::reserve(128 * 1024 * 1024).is_err());
    assert!(VerificationMemory::reserve(usize::MAX).is_err());
    let copies: Vec<_> = (0..1024).map(|_| owner.current()).collect();
    assert!(copies.iter().all(|copy| Arc::ptr_eq(copy, &first)));
    assert_eq!(
        1,
        first
            .source
            .pages
            .iter()
            .filter(|page| page.get().is_some())
            .count()
    );
    assert_eq!(
        None,
        first.source.pages[1].get().map(|_| ()),
        "no allocation for unadmitted pages"
    );
    drop(owner);
    drop(copies);
    check_bytes(&mut first.reader(), fixture.identity.length, 0x51)
        .expect("last pin remains valid");
}

#[test]
fn native_prefix_old_corruption_cannot_become_reused_typed_bytes_or_cold_authority() {
    let fixture = Fixture::new(2);
    let mut owner = fixture.open();
    fixture
        .file
        .write_all_at(&[0xee], 0)
        .expect("mutate old uncached block");
    fixture.file.sync_all().expect("sync mutation");
    // Old byte values and SHA state are reused from process admission, not
    // reinterpreted from changed disk contents on each new checkpoint.
    let next = append(&mut owner, &[0x62; 17]).expect("new extent validates independently");
    assert!(
        VerifiedAppendOwner::open(
            &fixture.path,
            next.identity,
            64 * 1024 * 1024,
            || Ok(()),
            |_| Ok(())
        )
        .is_err(),
        "cold admission hashes every selected byte"
    );
    assert!(
        next.read_exact_at(0, &mut [0]).is_err(),
        "cold row must verify the old digest"
    );
    assert!(next.is_failed());
}
