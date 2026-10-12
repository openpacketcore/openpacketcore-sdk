//! Read-only vocabulary admission before database or snapshot initialization.
//! This walks framing and canonical headers only. It grants no row or recovery
//! authority: the complete cold catalog and strict snapshot checks still run.

use super::*;

pub(crate) fn preflight_format(
    path: &Path,
    expected: PrefixIdentity,
    maximum: u64,
    cut_binding: [u8; 32],
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    let _owner = VerifiedAppendOwner::open(path, expected, maximum, check, |source| {
        let _memory = VerificationMemory::reserve(HEADER_MEMORY)?;
        let mut reader = Cursor {
            reader: source,
            position: 0,
            maximum: expected.length,
            hash: Sha256::new(),
        };
        let mut format = Format::read(&mut reader, true)?;
        if format < Format::V6 {
            return Err(invalid("native generation discriminator differs"));
        }
        let loaded = header::base(&mut reader, format)?;
        let base = &loaded.value;
        format.validate_context(&base.context)?;
        if base.binding != expected.binding
            || base.file_epoch != expected.file_epoch
            || base.block_bytes != expected.block_bytes
            || base.checkpoint_epoch > expected.checkpoint_epoch
            || base.operation_sequence > expected.operation_sequence
        {
            return Err(invalid(
                "native generation base differs from selected identity",
            ));
        }
        let mut context = base.context.clone();
        skip_rows(
            &mut reader,
            [
                context.business.counts[0],
                context.business.counts[1],
                context.business.counts[2],
                context.business.counts[3],
                context.log.count,
            ],
            context
                .business
                .roster
                .as_ref()
                .map_or([0; 2], |roster| roster.counts),
            check,
        )?;
        reader.boundary(base.block_bytes, check)?;
        let mut previous = reader.identity(
            base,
            base.checkpoint_epoch,
            base.operation_sequence,
            &context,
        )?;
        let mut actual_cut = base.cut_binding;
        while reader.position < expected.length {
            check()?;
            let next_format = Format::read(&mut reader, false)?;
            if next_format < format {
                return Err(invalid("native generation delta format regressed"));
            }
            format = next_format;
            let loaded = header::delta(&mut reader, format)?;
            let delta = &loaded.value;
            format.validate_context(&delta.after)?;
            if delta.previous != Previous::from(previous)
                || delta.before != context
                || previous.checkpoint_epoch.checked_add(1) != Some(delta.checkpoint_epoch)
                || delta.checkpoint_epoch > expected.checkpoint_epoch
                || delta.checkpoint_epoch == u64::MAX
                || delta.operation_sequence < previous.operation_sequence
                || delta.operation_sequence > expected.operation_sequence
            {
                return Err(invalid("native generation checkpoint predecessor differs"));
            }
            let roster = delta.roster_changed.ok_or_else(|| {
                invalid("native generation roster frame counts differ from its format")
            })?;
            skip_rows(&mut reader, delta.changed, roster, check)?;
            reader.boundary(base.block_bytes, check)?;
            context = delta.after.clone();
            previous = reader.identity(
                base,
                delta.checkpoint_epoch,
                delta.operation_sequence,
                &context,
            )?;
            actual_cut = delta.cut_binding;
        }
        // Interior bindings describe historical checkpoints in this file.
        if previous != expected || actual_cut != cut_binding {
            return Err(invalid(
                "native generation selected final extent or cut differs",
            ));
        }
        check()
    })?;
    check()
}

fn skip_bytes(
    reader: &mut Cursor<'_>,
    maximum: usize,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    let mut remaining = u32::from_le_bytes(reader.scalar()?) as usize;
    if remaining > maximum || remaining as u64 > reader.maximum - reader.position {
        return Err(invalid("native generation input extent exceeds bound"));
    }
    let mut bytes = Zeroizing::new([0; 8192]);
    while remaining != 0 {
        check()?;
        let count = remaining.min(bytes.len());
        reader.read_exact(&mut bytes[..count])?;
        remaining -= count;
    }
    check()
}

fn optional_bytes(
    reader: &mut Cursor<'_>,
    maximum: usize,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    if reader.present()? {
        skip_bytes(reader, maximum, check)?;
    }
    Ok(())
}

fn skip_rows(
    reader: &mut Cursor<'_>,
    counts: [usize; 5],
    roster: [usize; 2],
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<()> {
    if counts
        .into_iter()
        .chain(roster)
        .any(|count| count > validation::MAX_ITEMS)
    {
        return Err(invalid(
            "native generation changed count exceeds original bound",
        ));
    }
    for (tag, count) in counts.into_iter().enumerate() {
        for _ in 0..count {
            check()?;
            expect(reader, &[tag as u8])?;
            match tag {
                0 | 2 => {
                    reader.before()?;
                    skip_bytes(reader, MAX_ITEM, check)?;
                }
                1 => {
                    reader.before()?;
                    reader.scalar::<56>()?;
                    optional_bytes(reader, cold::MAX_BYTES, check)?;
                }
                3 => {
                    skip_bytes(reader, MAX_ITEM, check)?;
                }
                4 => {
                    reader.scalar::<8>()?;
                    reader.before()?;
                    optional_bytes(reader, sql::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES, check)?;
                }
                _ => return Err(invalid("native generation table tag differs")),
            }
        }
    }
    for _ in 0..roster[1] {
        check()?;
        expect(reader, &[5])?;
        reader.before()?;
        reader.scalar::<64>()?;
        reader.scalar::<16>()?;
        optional_bytes(reader, roster::frame::MAX_PARTITION, check)?;
        optional_bytes(reader, roster::frame::MAX_PARTITION, check)?;
    }
    for _ in 0..roster[0] {
        check()?;
        expect(reader, &[6])?;
        reader.before()?;
        reader.scalar::<120>()?;
        reader.scalar::<16>()?;
        optional_bytes(reader, roster::frame::MAX_ROW, check)?;
        optional_bytes(reader, roster::frame::MAX_ROW, check)?;
    }
    check()
}
