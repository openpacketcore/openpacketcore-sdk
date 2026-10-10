//! Paged ticket delivery. All notice contents remain untrusted hints.
use super::wire::*;
use sha2::{Digest, Sha256};

const MAX_PAGE_BYTES: usize = MAX_NOTICE_FRAME_BYTES - HEADER_BYTES - 32;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct NoticeBoot {
    pub(super) scope: ScopeBinding,
    pub(super) workload: [u8; 16],
    pub(super) process: [u8; 16],
    pub(super) key: [u8; 32],
}
#[derive(Clone)]
pub(super) struct ClosureHint {
    // Canonical native decoding and generation/scope comparisons happen at the
    // consumer boundary. This decoder produces only bounded untrusted claims.
    pub(super) predecessor: Vec<u8>,
    pub(super) kind: u8,
    pub(super) digest: [u8; 32],
    pub(super) record: Option<AuthorityReference>,
}
impl ClosureHint {
    fn write(&self, output: &mut Vec<u8>) -> Result<(), WireError> {
        if self.predecessor.is_empty()
            || self.predecessor.len() > MAX_AUTHORITY_BYTES
            || self.digest == [0; 32]
            || !matches!((self.kind, self.record.is_some()), (1, true) | (2, false))
        {
            return Err(WireError);
        }
        put_lp32(output, &self.predecessor)?;
        output.push(self.kind);
        output.extend_from_slice(&self.digest);
        if let Some(record) = &self.record {
            record.write(output)?;
        } else {
            output.push(0);
        }
        Ok(())
    }
}

/// Streaming commitment to one complete ordered evidence snapshot. Keeping the
/// preceding stamp enforces ordering across pages without retaining the set.
pub(super) struct NoticeCommitment {
    digest: Sha256,
    total: u32,
    next: u32,
    previous: Vec<u8>,
}
impl NoticeCommitment {
    pub(super) fn new(
        boot: &NoticeBoot,
        generation: u64,
        authority: &AuthorityReference,
        total: u32,
    ) -> Result<Self, WireError> {
        if boot.workload == [0; 16]
            || boot.process == [0; 16]
            || boot.key == [0; 32]
            || !(1..=i64::MAX as u64).contains(&generation)
        {
            return Err(WireError);
        }
        let mut input = b"openpacketcore/scope/ticket-notice-id/v1\0".to_vec();
        input.extend_from_slice(&boot.scope.encode());
        input.extend_from_slice(&boot.workload);
        input.extend_from_slice(&boot.process);
        input.extend_from_slice(&boot.key);
        input.extend_from_slice(&generation.to_be_bytes());
        authority.write(&mut input)?;
        input.extend_from_slice(&total.to_be_bytes());
        let mut digest = Sha256::new();
        digest.update(input);
        Ok(Self {
            digest,
            total,
            next: 0,
            previous: Vec::new(),
        })
    }
    pub(super) fn append(&mut self, entries: &[ClosureHint]) -> Result<(), WireError> {
        for entry in entries {
            if self.next >= self.total || self.previous.as_slice() >= entry.predecessor.as_slice() {
                return Err(WireError);
            }
            let mut bytes = Vec::new();
            entry.write(&mut bytes)?;
            self.digest.update(bytes);
            self.previous.clone_from(&entry.predecessor);
            self.next += 1;
        }
        Ok(())
    }
    pub(super) fn finish(self) -> Result<[u8; 16], WireError> {
        if self.next != self.total {
            return Err(WireError);
        }
        let mut id = [0; 16];
        id.copy_from_slice(&self.digest.finalize()[..16]);
        if id == [0; 16] {
            return Err(WireError);
        }
        Ok(id)
    }
}
#[derive(Clone)]
pub(super) struct NoticePage {
    pub(super) notice_id: [u8; 16],
    pub(super) boot: NoticeBoot,
    pub(super) generation: u64,
    pub(super) authority: AuthorityReference,
    pub(super) total: u32,
    pub(super) first: u32,
    pub(super) entries: Vec<ClosureHint>,
}
impl NoticePage {
    fn validate(&self) -> Result<(), WireError> {
        if self.notice_id == [0; 16]
            || self.boot.workload == [0; 16]
            || self.boot.process == [0; 16]
            || self.boot.key == [0; 32]
            || !(1..=i64::MAX as u64).contains(&self.generation)
            || self.first > self.total
        {
            return Err(WireError);
        }
        let count = (self.total - self.first).min(8) as usize;
        if self.entries.len() != count
            || (self.total > 0 && count == 0)
            || (self.total == 0 && self.first != 0)
        {
            return Err(WireError);
        }
        let mut previous: Option<&[u8]> = None;
        for entry in &self.entries {
            if entry.predecessor.is_empty()
                || entry.predecessor.len() > MAX_AUTHORITY_BYTES
                || entry.digest == [0; 32]
                || !matches!((entry.kind, entry.record.is_some()), (1, true) | (2, false))
                || previous.is_some_and(|value| value >= entry.predecessor.as_slice())
            {
                return Err(WireError);
            }
            previous = Some(&entry.predecessor);
        }
        Ok(())
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_PAGE_BYTES {
            return Err(WireError);
        }
        let mut reader = Reader::new(bytes);
        if reader.take(4)? != b"OPTN" || reader.u16()? != 1 {
            return Err(WireError);
        }
        let notice_id = reader.array()?;
        let boot = NoticeBoot {
            scope: ScopeBinding::read(&mut reader)?,
            workload: reader.array()?,
            process: reader.array()?,
            key: reader.array()?,
        };
        let generation = reader.u64()?;
        let authority = AuthorityReference::read(&mut reader)?.ok_or(WireError)?;
        let total = reader.u32()?;
        let first = reader.u32()?;
        let count = reader.u16()? as usize;
        if first > total
            || count > 8
            || count != (total - first).min(8) as usize
            || (total > 0 && count == 0)
        {
            return Err(WireError);
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(ClosureHint {
                predecessor: reader.lp32(MAX_AUTHORITY_BYTES)?.to_vec(),
                kind: reader.u8()?,
                digest: reader.array()?,
                record: AuthorityReference::read(&mut reader)?,
            });
        }
        reader.finish()?;
        let page = Self {
            notice_id,
            boot,
            generation,
            authority,
            total,
            first,
            entries,
        };
        page.validate()?;
        Ok(page)
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        let mut output = b"OPTN".to_vec();
        output.extend_from_slice(&1_u16.to_be_bytes());
        output.extend_from_slice(&self.notice_id);
        output.extend_from_slice(&self.boot.scope.encode());
        output.extend_from_slice(&self.boot.workload);
        output.extend_from_slice(&self.boot.process);
        output.extend_from_slice(&self.boot.key);
        output.extend_from_slice(&self.generation.to_be_bytes());
        self.authority.write(&mut output)?;
        output.extend_from_slice(&self.total.to_be_bytes());
        output.extend_from_slice(&self.first.to_be_bytes());
        output.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for entry in &self.entries {
            entry.write(&mut output)?;
        }
        if output.len() > MAX_PAGE_BYTES {
            return Err(WireError);
        }
        Ok(output)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct TicketHint {
    pub(super) notice_id: [u8; 16],
    pub(super) boot: NoticeBoot,
    pub(super) generation: u64,
    pub(super) authority: AuthorityReference,
}
struct InProgress {
    ticket: TicketHint,
    commitment: NoticeCommitment,
}
enum State {
    Empty,
    Receiving(InProgress),
    Complete(TicketHint),
    Poisoned,
}
/// Constant-memory page sequencing, independent of native claim verification.
/// A malformed page poisons the attempt; reconnect starts from page zero.
pub(super) struct NoticeSequence {
    boot: NoticeBoot,
    state: State,
}
impl NoticeSequence {
    pub(super) fn new(boot: NoticeBoot) -> Self {
        Self {
            boot,
            state: State::Empty,
        }
    }
    pub(super) fn accept_page(&mut self, page: NoticePage) -> Result<Vec<ClosureHint>, WireError> {
        let previous = std::mem::replace(&mut self.state, State::Poisoned);
        page.validate()?;
        if page.boot != self.boot {
            return Err(WireError);
        }
        let ticket = TicketHint {
            notice_id: page.notice_id,
            boot: page.boot,
            generation: page.generation,
            authority: page.authority,
        };
        let mut state = match previous {
            State::Empty => InProgress {
                ticket: ticket.clone(),
                commitment: NoticeCommitment::new(
                    &ticket.boot,
                    ticket.generation,
                    &ticket.authority,
                    page.total,
                )?,
            },
            State::Receiving(value) => value,
            State::Complete(_) | State::Poisoned => return Err(WireError),
        };
        if state.ticket != ticket
            || state.commitment.total != page.total
            || page.first != state.commitment.next
        {
            return Err(WireError);
        }
        state.commitment.append(&page.entries)?;
        self.state = if state.commitment.next == page.total {
            if state.commitment.finish()? != ticket.notice_id {
                return Err(WireError);
            }
            State::Complete(ticket)
        } else {
            State::Receiving(state)
        };
        Ok(page.entries)
    }
    pub(super) fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete(_))
    }
    pub(super) fn ticket(&self) -> Option<&TicketHint> {
        match &self.state {
            State::Complete(value) => Some(value),
            _ => None,
        }
    }
}
