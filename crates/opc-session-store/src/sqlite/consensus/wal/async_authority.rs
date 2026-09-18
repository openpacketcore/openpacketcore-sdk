//! Durable allocation limits for volatile incarnations.
//!
//! A selected session generation is a lower bound on acknowledged work. It
//! cannot also be the upper bound used to retire lost authority. This record
//! is separate from generation capture and must precede any use of its range.
//! Ordinary storage admission only compares resident values with this limit;
//! it never updates this file or waits for its writer.

use super::*;
use std::os::unix::fs::MetadataExt;

const NAME: &str = "ASYNC-AUTHORITY";
const PREPARING: &str = "ASYNC-AUTHORITY.preparing";
const MAGIC: &[u8; 8] = b"OPCAA001";
const BYTES: usize = 112;

// A range bounds actual authority issuance, not the size of a generation.
// Exhaustion fails closed; it must never silently reserve a range that another
// voter has not durably promised. There are 2^23 - 1 ranges in the signed
// counter vocabulary used by the native and portable storage formats.
const RANGE: u64 = 1 << 40;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reservation {
    era: u64,
}

impl Reservation {
    pub(crate) fn initial() -> Self {
        Self { era: 1 }
    }

    pub(crate) fn from_era(era: u64) -> io::Result<Self> {
        if era == 0 || era > (i64::MAX as u64) / RANGE {
            return Err(invalid_data("asynchronous authority range exhausted"));
        }
        Ok(Self { era })
    }

    pub(crate) fn ceiling(self) -> u64 {
        self.era * RANGE - 1
    }

    pub(crate) fn check(self, value: u64) -> io::Result<()> {
        if value > self.ceiling() {
            return Err(invalid_data("asynchronous authority range exceeded"));
        }
        Ok(())
    }
}

fn bytes(binding: Binding, reservation: Reservation) -> io::Result<[u8; BYTES]> {
    if !binding.async_recovery_format {
        return Err(invalid_data("asynchronous authority root format differs"));
    }
    let mut bytes = [0; BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..40].copy_from_slice(&binding.digest()?);
    bytes[40..48].copy_from_slice(&reservation.era.to_be_bytes());
    // Reserved, canonical zero bytes leave room for the recovery transition
    // commitment without accepting a second ambiguous representation.
    let digest = Sha256::digest(&bytes[..80]);
    bytes[80..].copy_from_slice(&digest);
    Ok(bytes)
}

pub(super) fn is_authority_file(name: &str, length: u64) -> io::Result<bool> {
    match name {
        NAME if length == BYTES as u64 => Ok(true),
        PREPARING if length <= BYTES as u64 => Ok(true),
        NAME | PREPARING => Err(invalid_data("asynchronous authority extent differs")),
        _ => Ok(false),
    }
}

fn require_name(path: &Path, file: &File, complete: bool) -> io::Result<()> {
    let retained = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if !named.is_file()
        || named.dev() != retained.dev()
        || named.ino() != retained.ino()
        || named.nlink() != 1
        || retained.nlink() != 1
        || retained.uid() != nix::unistd::geteuid().as_raw()
        || retained.mode() & 0o777 != 0o600
        || if complete {
            retained.len() != BYTES as u64
        } else {
            retained.len() > BYTES as u64
        }
    {
        return Err(invalid_data(
            "asynchronous authority namespace or ownership differs",
        ));
    }
    Ok(())
}

pub(super) fn create(
    directory: &Path,
    binding: Binding,
    control: &IoControl,
) -> io::Result<Reservation> {
    let reservation = Reservation::initial();
    let path = directory.join(NAME);
    (control.hook)(Point::BeforeAsyncAuthorityWrite)?;
    let mut output = file_create(&path)?;
    output.write_all(&bytes(binding, reservation)?)?;
    output.sync_all()?;
    (control.hook)(Point::AfterAsyncAuthorityFileSync)?;
    require_name(&path, &output, true)?;
    File::open(directory)?.sync_all()?;
    (control.hook)(Point::AfterAsyncAuthorityDirectorySync)?;
    require_name(&path, &output, true)?;
    Ok(reservation)
}

pub(super) fn read(directory: &Path, binding: Binding) -> io::Result<Reservation> {
    let path = directory.join(NAME);
    let mut input = file_read(&path)?;
    require_name(&path, &input, true)?;
    let mut encoded = [0; BYTES];
    input.read_exact(&mut encoded)?;
    let era = u64::from_be_bytes(
        encoded[40..48]
            .try_into()
            .map_err(|_| invalid_data("asynchronous authority range width differs"))?,
    );
    let reservation = Reservation::from_era(era)?;
    if encoded != bytes(binding, reservation)? {
        return Err(invalid_data("asynchronous authority binding differs"));
    }
    require_name(&path, &input, true)?;
    Ok(reservation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_reservation_has_a_strict_finite_ceiling() {
        let first = Reservation::initial();
        assert_eq!(first.ceiling(), RANGE - 1);
        assert!(first.check(first.ceiling()).is_ok());
        assert!(first.check(first.ceiling() + 1).is_err());
        assert!(Reservation::from_era(0).is_err());
        assert!(Reservation::from_era(u64::MAX).is_err());
        let last = Reservation::from_era((i64::MAX as u64) / RANGE).unwrap();
        assert!(last.ceiling() < i64::MAX as u64);
        assert!(Reservation::from_era(last.era + 1).is_err());
    }
}
