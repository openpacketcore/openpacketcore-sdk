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

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reservation {
    era: u64,
    plan: [u8; 32],
}

impl Reservation {
    pub(crate) fn initial() -> Self {
        Self {
            era: 1,
            plan: [0; 32],
        }
    }

    pub(crate) fn from_era(era: u64) -> io::Result<Self> {
        if era == 0 || era > (i64::MAX as u64) / RANGE {
            return Err(invalid_data("asynchronous authority range exhausted"));
        }
        Ok(Self { era, plan: [0; 32] })
    }

    pub(crate) fn recovery(era: u64, plan: [u8; 32]) -> io::Result<Self> {
        let mut reservation = Self::from_era(era)?;
        if era < 2 || plan == [0; 32] {
            return Err(invalid_data("asynchronous authority promise differs"));
        }
        reservation.plan = plan;
        Ok(reservation)
    }

    pub(crate) fn plan(self) -> [u8; 32] {
        self.plan
    }

    pub(crate) fn ceiling(self) -> u64 {
        self.era * RANGE - 1
    }

    pub(crate) fn era(self) -> u64 {
        self.era
    }

    pub(crate) fn retired_through(self) -> u64 {
        (self.era - 1).saturating_mul(RANGE).saturating_sub(1)
    }

    pub(crate) fn check(self, value: u64) -> io::Result<()> {
        if value > self.ceiling() {
            return Err(invalid_data("asynchronous authority range exceeded"));
        }
        Ok(())
    }
}

fn bytes(binding: Binding, reservation: Reservation) -> io::Result<[u8; BYTES]> {
    if !binding.async_recovery_format || (reservation.era == 1) != (reservation.plan == [0; 32]) {
        return Err(invalid_data("asynchronous authority root format differs"));
    }
    let mut bytes = [0; BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..40].copy_from_slice(&binding.digest()?);
    bytes[40..48].copy_from_slice(&reservation.era.to_be_bytes());
    bytes[48..80].copy_from_slice(&reservation.plan);
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
    let plan: [u8; 32] = encoded[48..80]
        .try_into()
        .map_err(|_| invalid_data("asynchronous authority promise width differs"))?;
    let reservation = if era == 1 && plan == [0; 32] {
        Reservation::initial()
    } else {
        Reservation::recovery(era, plan)?
    };
    if encoded != bytes(binding, reservation)? {
        return Err(invalid_data("asynchronous authority binding differs"));
    }
    require_name(&path, &input, true)?;
    Ok(reservation)
}

fn retire_staging(directory: &Path) -> io::Result<()> {
    let path = directory.join(PREPARING);
    let file = match file_read(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    // This inode has never been selected. Incomplete preparation must not
    // supply authority, and must not prevent a later strictly newer round.
    require_name(&path, &file, false)?;
    fs::remove_file(&path)?;
    File::open(directory)?.sync_all()
}

fn advance(
    directory: &Path,
    binding: Binding,
    before: Reservation,
    after: Reservation,
    control: &IoControl,
) -> io::Result<()> {
    let old = file_read(&directory.join(NAME))?;
    require_name(&directory.join(NAME), &old, true)?;
    if read(directory, binding)? != before || after.era <= before.era {
        return Err(invalid_data("asynchronous authority predecessor differs"));
    }
    let encoded = bytes(binding, after)?;
    retire_staging(directory)?;
    (control.hook)(Point::BeforeAsyncAuthorityWrite)?;
    let mut output = file_create(&directory.join(PREPARING))?;
    output.write_all(&encoded)?;
    output.sync_all()?;
    (control.hook)(Point::AfterAsyncAuthorityFileSync)?;
    require_name(&directory.join(PREPARING), &output, true)?;
    require_name(&directory.join(NAME), &old, true)?;
    if read(directory, binding)? != before {
        return Err(invalid_data("asynchronous authority predecessor changed"));
    }
    fs::rename(directory.join(PREPARING), directory.join(NAME))?;
    (control.hook)(Point::AfterAsyncAuthorityRename)?;
    require_name(&directory.join(NAME), &output, true)?;
    if old.metadata()?.nlink() != 0 {
        return Err(invalid_data("asynchronous authority replacement differs"));
    }
    File::open(directory)?.sync_all()?;
    (control.hook)(Point::AfterAsyncAuthorityDirectorySync)?;
    require_name(&directory.join(NAME), &output, true)?;
    if read(directory, binding)? != after {
        return Err(invalid_data("asynchronous authority publication changed"));
    }
    Ok(())
}

impl Wal {
    pub(crate) fn async_covers_committed(
        &self,
        cuts: &[LogId<SessionConsensusNodeId>],
    ) -> io::Result<bool> {
        let state = lock_state(&self.shared)?;
        native::ensure_native_public_owner(&state)?;
        let native = state
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("asynchronous retained state absent"))?;
        let covers = |last: LogId<SessionConsensusNodeId>, cut: LogId<SessionConsensusNodeId>| {
            last.index >= cut.index
                && last.leader_id >= cut.leader_id
                && (last.index != cut.index || last == cut)
        };
        Ok(cuts.iter().all(|cut| {
            if let Some(entry) = native.log.entries.get(&cut.index) {
                return entry.id() == *cut;
            }
            // A validated installed/purged committed prefix has already been
            // applied. Before this unanimous freeze, cold admission never
            // allowed a lost incarnation to create a competing committed
            // history. Exact retained LogIds are compared above; a purged
            // prefix keeps its complete admitted cut and cannot be lowered.
            native.log.purged.is_some_and(|purged| {
                covers(purged, *cut)
                    && native
                        .business
                        .applied()
                        .is_some_and(|applied| covers(applied, purged))
            })
        }))
    }

    pub(crate) fn async_retained(&self) -> io::Result<crate::consensus::recovery_types::Retained> {
        let state = lock_state(&self.shared)?;
        native::ensure_native_public_owner(&state)?;
        let native = state
            .native
            .as_ref()
            .ok_or_else(|| invalid_data("asynchronous retained state absent"))?;
        let progress = state
            .asynchronous
            .as_ref()
            .ok_or_else(|| invalid_data("asynchronous retained progress absent"))?;
        if progress.failure.is_some() {
            return Err(invalid_data("asynchronous retained persistence failed"));
        }
        Ok(crate::consensus::recovery_types::Retained {
            vote: native.log.vote,
            last: native.log.last(),
            committed: native.log.committed,
            applied: native.business.applied(),
            purged: native.log.purged,
            membership: *native.business.membership().log_id(),
            boundary: native.business.async_recovery_boundary(),
            generation: progress.generation,
            completed_generation: progress.completed.generation,
            sequence: state.sequence,
            completed_sequence: progress.completed.sequence,
            busy: state.native_operations != 0
                || state.native_install_pending
                || state.snapshot.is_some(),
        })
    }

    pub(crate) fn async_authority(&self) -> io::Result<Option<([u8; 32], Reservation)>> {
        let state = lock_state(&self.shared)?;
        native::ensure_native_public_owner(&state)?;
        state
            .async_authority
            .map(|reservation| self.binding.digest().map(|root| (root, reservation)))
            .transpose()
    }

    /// The caller owns the recovery admission fence. Once accepted, a blocking
    /// supervisor retains this WAL owner until the disk transition completes.
    /// No ordinary engine effect may be admitted using the new range earlier.
    pub(crate) fn promise_async_authority(
        &self,
        before: Reservation,
        after: Reservation,
    ) -> io::Result<()> {
        let _operation = self.native_operation()?;
        let state = lock_state(&self.shared)?;
        native::ensure_native_public_owner(&state)?;
        let current = state
            .async_authority
            .ok_or_else(|| invalid_data("asynchronous authority reservation absent"))?;
        if after.era <= before.era || after.plan == [0; 32] {
            return Err(invalid_data("asynchronous authority successor differs"));
        }
        if state
            .asynchronous
            .as_ref()
            .is_none_or(|progress| progress.failure.is_some())
            || state.consensus_closed
            || (current != before && current != after)
        {
            return Err(invalid_data("asynchronous authority owner differs"));
        }
        // Keep the accepted operation/root owner, not the resident state lock,
        // across disk I/O. Passive health and deadline-bound control requests
        // must remain pollable while a sync is delayed. The caller holds the
        // exclusive recovery admission fence and serializes local promises.
        drop(state);
        let result = if current == after {
            read(&self.directory, self.binding).and_then(|disk| {
                if disk == after {
                    Ok(())
                } else {
                    Err(invalid_data("asynchronous authority retry differs"))
                }
            })
        } else {
            advance(&self.directory, self.binding, before, after, &self.control)
        };
        let mut state = lock_state(&self.shared)?;
        let result = result.and_then(|()| {
            ensure_readable(&state)?;
            if !matches!(state.status, Status::Running | Status::Closing)
                || state.async_authority != Some(current)
            {
                return Err(invalid_data(
                    "asynchronous authority publication owner changed",
                ));
            }
            Ok(())
        });
        if let Err(error) = result {
            application::record_failure(
                &mut state,
                SessionStorageFailure::from_io(SessionStorageFailureStage::Persistence, &error),
            );
            application::fence(&mut state);
            self.shared.ready.notify_all();
            return Err(error);
        }
        state.async_authority = Some(after);
        Ok(())
    }
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
