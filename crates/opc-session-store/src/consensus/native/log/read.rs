//! A log read linearizes at its immutable root capture. Concurrent Raft
//! truncation, purge and append can change the live root without changing
//! that admitted view. Selected bytes are read only after State is released;
//! the WAL adapter must recheck its running owner before returning the result.

use super::*;
use crate::consensus::verified_snapshot::VerificationMemory;
use std::mem::size_of;
use std::sync::Arc;

pub(crate) struct LogReadCapture {
    log: NativeLog,
    business: Arc<crate::consensus::native::changes::BusinessProof>,
    _memory: VerificationMemory,
}

pub(crate) struct LogReadResult {
    entries: Vec<Entry<SessionRaftTypeConfig>>,
    // Independent copies retain their charges through the adapter's final
    // owner check. Drop ordering destroys models before refunding on errors.
    guards: Vec<VerificationMemory>,
    _memory: VerificationMemory,
}

impl LogReadResult {
    pub(crate) fn entries(&self) -> &[Entry<SessionRaftTypeConfig>] {
        &self.entries
    }
    pub(crate) fn into_entries(self) -> Vec<Entry<SessionRaftTypeConfig>> {
        self.entries
    }
}

impl NativeStorage {
    /// Only a shared persistent-tree root and proof handles are copied while
    /// State is held. No range traversal, file read or codec executes here.
    pub(crate) fn capture_log_read(&self) -> io::Result<LogReadCapture> {
        self.log.require_proof(&self.business)?;
        let memory = VerificationMemory::reserve(size_of::<LogReadCapture>() + 4096)?;
        Ok(LogReadCapture {
            log: self.log.clone(),
            business: Arc::clone(self.business.require_business_proof()?),
            _memory: memory,
        })
    }
}

impl LogReadCapture {
    pub(crate) fn require_current_authority(&self, current: &NativeStorage) -> io::Result<()> {
        current.log.require_proof(&current.business)?;
        let (identity, members, _) = self.business.context();
        let (current_identity, current_members, _) =
            current.business.require_business_proof()?.context();
        if identity != current_identity || members != current_members {
            return Err(invalid("native log read authority changed"));
        }
        Ok(())
    }

    /// All requested rows are bounded by the already-admitted retained log.
    /// Their complete codecs and independent result allocations stay outside
    /// State, including the result container's allocation and growth.
    pub(crate) fn resolve(
        &self,
        start: u64,
        end: Option<u64>,
        limit: Option<usize>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<LogReadResult> {
        check()?;
        let start = self
            .log
            .purged
            .map_or(start, |floor| start.max(floor.index + 1));
        let end = end.unwrap_or(COUNTER_MAX + 1);
        let limit = limit.unwrap_or(MAX_RETAINED_LOG_ENTRIES);
        let count = if start < end {
            self.log.entries.range(start..end).take(limit).count()
        } else {
            0
        };
        let bytes = count
            .checked_mul(
                2 * (size_of::<Entry<SessionRaftTypeConfig>>() + size_of::<VerificationMemory>()),
            )
            .and_then(|bytes| bytes.checked_add(size_of::<LogReadResult>()))
            .ok_or_else(|| invalid("native log read container reservation overflow"))?;
        let memory = VerificationMemory::reserve(bytes)?;
        let mut result = LogReadResult {
            entries: Vec::new(),
            guards: Vec::new(),
            _memory: memory,
        };
        result
            .entries
            .try_reserve_exact(count)
            .map_err(|_| invalid("native log read output allocation failed"))?;
        result
            .guards
            .try_reserve_exact(count)
            .map_err(|_| invalid("native log read guard allocation failed"))?;
        if count == 0 {
            return Ok(result);
        }
        let (identity, members, _) = self.business.context();
        for (index, row) in self.log.entries.range(start..end).take(limit) {
            check()?;
            let owned = row.read_owned(*index, identity, members, check)?;
            if owned.entry().log_id != row.id() {
                return Err(invalid("native log read ID differs from captured row"));
            }
            let (entry, memory) = owned.into_parts();
            result.entries.push(entry);
            result.guards.push(memory);
        }
        check()?;
        Ok(result)
    }
}
