//! Rebind a selected frame's physical predecessor without changing its body.
//! Authority comes from the ordinary authenticated source, canonical typed
//! header/continuity, exact second-read comparison, and cold admission on reopen.

use super::*;

#[derive(Clone, Copy)]
pub(crate) struct FrameShift {
    pub(crate) old_body: u64,
    pub(crate) new_body: u64,
    pub(crate) length: u64,
}

pub(crate) struct FrameMapping {
    pub(crate) value: FrameShift,
    pub(crate) _memory: VerificationMemory,
}

#[cfg(test)]
pub(crate) fn rebase_frame(
    old_end: Arc<VerifiedPrefix>,
    start: PrefixIdentity,
    payload_bytes: u64,
    target: &mut VerifiedAppendOwner,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<(Arc<VerifiedPrefix>, FrameShift)> {
    rebase_frame_with_reserve(old_end, start, payload_bytes, target, 0, check)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "native candidate capacity exhausted",
        )
    })
}

pub(crate) fn try_rebase_frame(
    old_end: Arc<VerifiedPrefix>,
    start: PrefixIdentity,
    payload_bytes: u64,
    target: &mut VerifiedAppendOwner,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<Option<(Arc<VerifiedPrefix>, FrameShift)>> {
    rebase_frame_with_reserve(old_end, start, payload_bytes, target, 0, check)
}

pub(super) fn rebase_frame_with_reserve(
    old_end: Arc<VerifiedPrefix>,
    start: PrefixIdentity,
    payload_bytes: u64,
    target: &mut VerifiedAppendOwner,
    switch_reserve: u64,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<Option<(Arc<VerifiedPrefix>, FrameShift)>> {
    let _memory = VerificationMemory::reserve(HEADER_MEMORY + 8192)?;
    let old = old_end.identity();
    let before = target.current();
    let new = before.identity();
    if start.block_bytes != old.block_bytes {
        return Err(invalid("rebase block width differs"));
    }
    let payload_end = start
        .length
        .checked_add(payload_bytes)
        .ok_or_else(|| invalid("rebase extent overflow"))?;
    let rounded = payload_end
        .checked_add(start.block_bytes as u64 - 1)
        .map(|n| n / start.block_bytes as u64 * start.block_bytes as u64)
        .ok_or_else(|| invalid("rebase extent overflow"))?;
    if payload_bytes == 0
        || rounded != old.length
        || start.binding != old.binding
        || start.file_epoch != old.file_epoch
        || start.block_bytes != old.block_bytes
        || new.binding != start.binding
        || new.block_bytes != start.block_bytes
        || new.frontiers != start.frontiers
        || new.checkpoint_epoch != start.checkpoint_epoch
        || new.operation_sequence != start.operation_sequence
    {
        return Err(invalid("rebase selected predecessor differs"));
    }
    let mut input = Range {
        view: Arc::clone(&old_end),
        offset: start.length,
        end: payload_end,
    };
    let mut magic = [0; 8];
    input.read_exact(&mut magic)?;
    if &magic != MAGIC && &magic != SLOT_MAGIC {
        return Err(invalid("rebase frame format differs"));
    }
    let bytes = read_bytes(&mut input, MAX_HEADER)?;
    let mut header: Header =
        serde_json::from_slice(bytes.bytes()).map_err(|_| invalid("rebase header invalid"))?;
    if serde_json::to_vec(&header).map_err(|_| invalid("rebase header cannot encode"))?
        != bytes.bytes()
        || header.previous != Previous::from(start)
        || header.before.digest()? != new.frontiers
        || start.checkpoint_epoch.checked_add(1) != Some(header.checkpoint_epoch)
        || header.checkpoint_epoch == u64::MAX
        || header.checkpoint_epoch != old.checkpoint_epoch
        || header.operation_sequence < start.operation_sequence
        || header.operation_sequence != old.operation_sequence
        || header.after.digest()? != old.frontiers
    {
        return Err(invalid("rebase header continuity differs"));
    }
    let old_body = input.offset;
    let body_bytes = payload_end
        .checked_sub(old_body)
        .ok_or_else(|| invalid("rebase body extent invalid"))?;
    if body_bytes < END.len() as u64 {
        return Err(invalid("rebase body truncated"));
    }
    let mut end = [0; 8];
    old_end.read_exact_at(payload_end - END.len() as u64, &mut end)?;
    if &end != END {
        return Err(invalid("rebase body terminator differs"));
    }
    header.previous = new.into();
    // Only CURRENT's final frame binds the new file's selector. Intermediate
    // cut bindings stay byte-identical, as required by the existing format.
    let encoded = Zeroizing::new(
        serde_json::to_vec(&header).map_err(|_| invalid("rebase header cannot encode"))?,
    );
    let new_body = new
        .length
        .checked_add(12)
        .and_then(|n| n.checked_add(encoded.len() as u64))
        .ok_or_else(|| invalid("rebase header extent overflow"))?;
    let payload = new_body
        .checked_sub(new.length)
        .and_then(|n| n.checked_add(body_bytes))
        .ok_or_else(|| invalid("rebase payload overflow"))?;
    let write = |writer: &mut dyn Write| -> io::Result<()> {
        check()?;
        writer.write_all(&magic)?;
        write_bytes(writer, &encoded, MAX_HEADER)?;
        let mut source = Range {
            view: Arc::clone(&old_end),
            offset: old_body,
            end: payload_end,
        };
        let mut buffer = Zeroizing::new([0; 8192]);
        while source.offset != source.end {
            check()?;
            let count = source.read(&mut *buffer)?;
            writer.write_all(&buffer[..count])?;
        }
        check()
    };
    let view = target.append_with_reserve(
        &before,
        crate::consensus::native::prefix::AppendTransaction {
            checkpoint_epoch: header.checkpoint_epoch,
            operation_sequence: header.operation_sequence,
            frontiers: header.after.digest()?,
            payload_bytes: payload,
        },
        switch_reserve,
        check,
        write,
        |reader| {
            {
                // This independently reads the authenticated old body again; it
                // does not compare a hash or trust the first copy's scratch.
                let mut comparison = crate::consensus::native::prefix::CompareWriter::new(reader);
                write(&mut comparison)?;
            }
            let mut extra = [0];
            if reader.read(&mut extra)? != 0 {
                return Err(invalid("rebase trailing bytes"));
            }
            Ok(())
        },
    )?;
    Ok(view.map(|view| {
        (
            view,
            FrameShift {
                old_body,
                new_body,
                length: body_bytes,
            },
        )
    }))
}

struct Range {
    view: Arc<VerifiedPrefix>,
    offset: u64,
    end: u64,
}
impl Read for Range {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = usize::try_from(self.end - self.offset)
            .unwrap_or(usize::MAX)
            .min(output.len());
        self.view.read_exact_at(self.offset, &mut output[..count])?;
        self.offset += count as u64;
        Ok(count)
    }
}
