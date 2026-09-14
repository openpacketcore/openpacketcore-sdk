//! Exact log after-images, including explicit missing-row tombstones. The
//! original complete JSON decoder remains the log schema authority.

use super::*;
use crate::consensus::native::generation::{self as frame, LogContext};
use std::io::Write;

impl GenerationLogVersion {
    pub(in crate::consensus::native) fn context(&self) -> LogContext {
        let value = &self.0;
        LogContext {
            vote: value.frontiers.vote,
            committed: value.frontiers.committed,
            purged: value.frontiers.purged,
            count: value.summary.count,
            content: value.summary.content,
            first: value.first,
            last: value.last,
        }
    }
}

impl NativeLog {
    pub(in crate::consensus::native) fn generation_versions(
        &self,
        state: &NativeState,
    ) -> io::Result<(Arc<BusinessProof>, GenerationLogVersion)> {
        let (business, log) = self.require_proofs(state)?;
        Ok((Arc::clone(business), GenerationLogVersion(Arc::clone(log))))
    }

    pub(in crate::consensus::native) fn generation_version(
        &self,
        state: &NativeState,
    ) -> io::Result<GenerationLogVersion> {
        Ok(GenerationLogVersion(Arc::clone(self.require_proof(state)?)))
    }
}

impl CapturedLog {
    pub(in crate::consensus::native) fn generation_starts_at(
        &self,
        version: &GenerationLogVersion,
    ) -> bool {
        Arc::ptr_eq(&self.changes.base, &version.0)
    }

    pub(in crate::consensus::native) fn generation_target(&self) -> GenerationLogVersion {
        GenerationLogVersion(Arc::clone(&self.changes.target))
    }

    pub(in crate::consensus::native) fn generation_count(&self) -> usize {
        self.changes.rows.len()
    }

    pub(in crate::consensus::native) fn write_generation(
        &self,
        writer: &mut dyn Write,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        for (index, change) in &self.changes.rows {
            check()?;
            writer.write_all(&[4])?;
            writer.write_all(&index.to_le_bytes())?;
            frame::write_before(writer, change.before_stamp.map(|stamp| stamp.content))?;
            writer.write_all(&[u8::from(change.after.is_some())])?;
            if let Some(row) = &change.after {
                frame::write_bytes(
                    writer,
                    &row.resident()?.encoded,
                    sql::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES,
                )?;
            }
        }
        check()
    }

    pub(in crate::consensus::native) fn verify_generation(
        &self,
        reader: &mut frame::PositionedReader<'_>,
        check: &impl Fn() -> io::Result<()>,
        mut relocations: Option<&mut frame::RelocationBuilder>,
    ) -> io::Result<()> {
        let (identity, members, _) = self.business.context();
        for (index, change) in &self.changes.rows {
            check()?;
            frame::expect(reader, &[4])?;
            frame::expect(reader, &index.to_le_bytes())?;
            frame::expect_before(reader, change.before_stamp.map(|stamp| stamp.content))?;
            frame::expect(reader, &[u8::from(change.after.is_some())])?;
            if let Some(row) = &change.after {
                let resident = row.resident()?;
                let offset = reader
                    .position()
                    .checked_add(4)
                    .ok_or_else(|| invalid("native log relocation offset overflow"))?;
                let input = frame::read_bytes(reader, resident.encoded.len())?;
                if input.bytes() != resident.encoded.as_ref() {
                    return Err(invalid(
                        "native generation log differs from exact captured bytes",
                    ));
                }
                scratch::log(row, check, || {
                    let decoded = sql::decode_consensus_log_entry(input.bytes())?;
                    if decoded != resident.entry || decoded.log_id.index != *index {
                        return Err(invalid("native generation raw and typed log differ"));
                    }
                    NativeLog::validate_entry_context(&decoded, identity, members)
                })?;
                if let Some(relocations) = &mut relocations {
                    relocations.log(*index, row, offset, input.bytes().len() as u32)?;
                }
            }
        }
        check()
    }
}
