//! One-use evidence that a consensus incarnation ended without a volatile tail.
//!
//! The caller first joins Raft and every storage owner. The writer then drains
//! its final generation and publishes this proof before releasing LOCK. A cold
//! opener validates the complete root/selection/snapshot first, and durably
//! consumes the proof before starting any writer or consensus participant.
//! This authorizes ordinary Raft restart checks, never traffic or a new lease.
//!
//! Only the new Async ROOT format supports this proof: an older SDK must reject
//! the root rather than leave an unconsumed certificate beside new volatile work.

use super::*;
use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;

const NAME: &str = "ASYNC-CLOSED";
const PREPARING: &str = "ASYNC-CLOSED.preparing";
const MAGIC: &[u8; 8] = b"OPCAC001";
const BYTES: usize = 136;

pub(super) fn is_proof_file(name: &str, length: u64) -> io::Result<bool> {
    match name {
        NAME if length == BYTES as u64 => Ok(true),
        PREPARING if length <= BYTES as u64 => Ok(true),
        NAME | PREPARING => Err(invalid_data(
            "closed incarnation publication extent differs",
        )),
        _ => Ok(false),
    }
}

fn bytes(
    binding: Binding,
    anchor: &checkpoint::Anchor,
    native: &crate::consensus::native::NativeStorage,
) -> io::Result<[u8; BYTES]> {
    if binding.persistence != SessionPersistenceMode::Async || anchor.async_cut.is_none() {
        return Err(invalid_data(
            "closed incarnation requires an asynchronous cut",
        ));
    }
    if !binding.async_closed_format || anchor.root != binding.digest()? {
        return Err(invalid_data("closed incarnation root format differs"));
    }
    let mut bytes = [0; BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..40].copy_from_slice(&binding.digest()?);
    // The complete selected anchor binds the generation, sequence, full LogIds,
    // immutable extent/frontiers and any retained installed snapshot origin.
    bytes[40..72].copy_from_slice(&Sha256::digest(encode_json(anchor)?));
    // Explicit full vote and exact membership, never only a scalar term/index.
    bytes[72..104].copy_from_slice(&Sha256::digest(encode_json(&(
        native.log.vote,
        native.log.committed,
        native.log.purged,
        native.business.members(),
    ))?));
    let digest = Sha256::digest(&bytes[..104]);
    bytes[104..].copy_from_slice(&digest);
    Ok(bytes)
}

fn file(path: &Path) -> io::Result<Option<File>> {
    let file = match file_read(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let meta = file.metadata()?;
    if meta.uid() != nix::unistd::geteuid().as_raw()
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
        || meta.len() > BYTES as u64
    {
        return Err(invalid_data(
            "closed incarnation file ownership or extent differs",
        ));
    }
    Ok(Some(file))
}

fn require_name(path: &Path, descriptor: &File) -> io::Result<()> {
    let retained = descriptor.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if !named.is_file()
        || named.dev() != retained.dev()
        || named.ino() != retained.ino()
        || named.nlink() != 1
    {
        return Err(invalid_data("closed incarnation namespace changed"));
    }
    Ok(())
}

pub(super) fn publish(
    state: &State,
    disk: &Disk,
    binding: Binding,
    control: &IoControl,
) -> io::Result<()> {
    let progress = state
        .asynchronous
        .as_ref()
        .ok_or_else(|| invalid_data("closed incarnation progress missing"))?;
    let anchor = disk
        .anchor
        .as_ref()
        .ok_or_else(|| invalid_data("closed incarnation selector missing"))?;
    let native = state
        .native
        .as_ref()
        .ok_or_else(|| invalid_data("closed incarnation native state missing"))?;
    if !state.consensus_closed
        || !progress.caught_up()
        || progress.failure.is_some()
        || state.failure.is_some()
        || state.native_operations != 0
        || anchor.async_cut != Some(progress.completed)
        || progress.completed.sequence != state.sequence
        || progress.completed.committed != native.log.committed
        || progress.completed.applied != native.business.applied()
    {
        return Err(invalid_data(
            "closed incarnation does not cover the final owner",
        ));
    }
    (control.hook)(Point::BeforeAsyncClosedWrite)?;
    let mut output = file_create(&disk.directory.join(PREPARING))?;
    output.write_all(&bytes(binding, anchor, native)?)?;
    output.sync_all()?;
    (control.hook)(Point::AfterAsyncClosedFileSync)?;
    // The previous proof must have been consumed before this incarnation ran.
    match fs::symlink_metadata(disk.directory.join(NAME)) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
        Ok(_) => {
            return Err(invalid_data(
                "closed incarnation predecessor was not consumed",
            ))
        }
    }
    require_name(&disk.directory.join(PREPARING), &output)?;
    let directory = File::open(&disk.directory)?;
    crate::consensus::snapshot::rename_noreplace_in_directory(
        &directory,
        OsStr::new(PREPARING),
        OsStr::new(NAME),
    )?;
    (control.hook)(Point::AfterAsyncClosedRename)?;
    require_name(&disk.directory.join(NAME), &output)?;
    directory.sync_all()?;
    (control.hook)(Point::AfterAsyncClosedDirectorySync)?;
    Ok(())
}

pub(super) fn consume(
    directory: &Path,
    binding: Binding,
    anchor: &checkpoint::Anchor,
    native: &crate::consensus::native::NativeStorage,
    control: &IoControl,
) -> io::Result<bool> {
    // Incomplete publication grants no authority. This is only a private
    // staging inode under the admitted, exclusively locked native directory.
    if let Some(staging) = file(&directory.join(PREPARING))? {
        require_name(&directory.join(PREPARING), &staging)?;
        fs::remove_file(directory.join(PREPARING))?;
        File::open(directory)?.sync_all()?;
    }
    let Some(mut input) = file(&directory.join(NAME))? else {
        return Ok(false);
    };
    let mut proof = [0; BYTES];
    input.read_exact(&mut proof)?;
    if input.metadata()?.len() != BYTES as u64 || proof != bytes(binding, anchor, native)? {
        return Err(invalid_data(
            "closed incarnation proof differs from selected authority",
        ));
    }
    (control.hook)(Point::BeforeAsyncClosedConsume)?;
    require_name(&directory.join(NAME), &input)?;
    input.rewind()?;
    let mut current = [0; BYTES];
    input.read_exact(&mut current)?;
    if current != proof || input.metadata()?.len() != BYTES as u64 {
        return Err(invalid_data("closed incarnation content changed"));
    }
    fs::remove_file(directory.join(NAME))?;
    (control.hook)(Point::AfterAsyncClosedUnlink)?;
    File::open(directory)?.sync_all()?;
    (control.hook)(Point::AfterAsyncClosedConsumeSync)?;
    Ok(true)
}
