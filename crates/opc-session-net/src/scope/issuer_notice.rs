//! Bounded ticket notices delivered on the same verified startup connection.
use super::{
    issuer::IssuerStartupSession, notice::ClosureHint, startup::StartupError,
    wire::AuthorityReference,
};
use opc_session_store::scope_authority::{
    ScopeAuthorityStamp, ScopeClosureEvidence, ScopeClosureKind,
};

/// Durable issuance facts to announce after the issuer has committed its record.
/// Delivery is a hint; admission independently reads current issuance again.
pub struct IssuedTicketNotice {
    pub(super) generation: u64,
    pub(super) authority: AuthorityReference,
    pub(super) total_predecessors: u32,
}
impl IssuedTicketNotice {
    /// Name the committed issuance and the count of all unresolved predecessors.
    pub fn new(
        generation: u64,
        record_uid: Vec<u8>,
        revision: Vec<u8>,
        total_predecessors: u32,
    ) -> Result<Self, StartupError> {
        if !(1..=i64::MAX as u64).contains(&generation) {
            return Err(StartupError::Invalid);
        }
        let authority =
            AuthorityReference::new(record_uid, revision).map_err(|_| StartupError::Invalid)?;
        Ok(Self {
            generation,
            authority,
            total_predecessors,
        })
    }
    pub(super) async fn id_for(
        &self,
        boot: &super::notice::NoticeBoot,
        source: &dyn TicketNoticeSource,
    ) -> Result<[u8; 16], StartupError> {
        let mut commitment = super::notice::NoticeCommitment::new(
            boot,
            self.generation,
            &self.authority,
            self.total_predecessors,
        )
        .map_err(|_| StartupError::Invalid)?;
        let mut first = 0;
        loop {
            let page = self.page(boot, [1; 16], first, source).await?;
            commitment
                .append(&page.entries)
                .map_err(|_| StartupError::Invalid)?;
            first = first
                .checked_add(page.entries.len() as u32)
                .ok_or(StartupError::Invalid)?;
            if first == self.total_predecessors {
                return commitment.finish().map_err(|_| StartupError::Invalid);
            }
        }
    }
    async fn page(
        &self,
        boot: &super::notice::NoticeBoot,
        notice_id: [u8; 16],
        first: u32,
        source: &dyn TicketNoticeSource,
    ) -> Result<super::notice::NoticePage, StartupError> {
        let count = self
            .total_predecessors
            .checked_sub(first)
            .ok_or(StartupError::Invalid)?
            .min(8) as u8;
        let entries = source.page(first, count).await?;
        if entries.len() != usize::from(count) {
            return Err(StartupError::Invalid);
        }
        let page = super::notice::NoticePage {
            notice_id,
            boot: boot.clone(),
            generation: self.generation,
            authority: self.authority.clone(),
            total: self.total_predecessors,
            first,
            entries: entries.into_iter().map(|entry| entry.hint).collect(),
        };
        page.encode().map_err(|_| StartupError::Invalid)?;
        Ok(page)
    }
}
/// One exact predecessor and the independently retained evidence to cite.
pub struct TicketNoticeEntry {
    pub(super) hint: ClosureHint,
}
impl TicketNoticeEntry {
    /// Encode a native predecessor. Final termination requires an immutable
    /// record reference; committed Close uses its native digest without one.
    pub fn new(
        predecessor: &ScopeAuthorityStamp,
        evidence: &ScopeClosureEvidence,
        record: Option<(Vec<u8>, Vec<u8>)>,
    ) -> Result<Self, StartupError> {
        let record = record
            .map(|(uid, revision)| AuthorityReference::new(uid, revision))
            .transpose()
            .map_err(|_| StartupError::Invalid)?;
        let kind = match (evidence.kind(), record.is_some()) {
            (ScopeClosureKind::FinalTermination, true) => 1,
            (ScopeClosureKind::CommittedClose, false) => 2,
            _ => return Err(StartupError::Invalid),
        };
        Ok(Self {
            hint: ClosureHint {
                predecessor: predecessor
                    .encode_canonical()
                    .map_err(|_| StartupError::Invalid)?,
                kind,
                digest: *evidence.digest(),
                record,
            },
        })
    }
}
/// Bounded page reader over one immutable delivery snapshot. Entries are ordered
/// by canonical predecessor bytes and include every unresolved possible
/// predecessor. Each delivery reads the snapshot twice: to compute its content
/// commitment, then to send it. Both passes must return identical entries.
/// A fresh delivery may rebuild this snapshot from current committed authority
/// and retained evidence, while keeping the same ticket generation and record.
#[async_trait::async_trait]
pub trait TicketNoticeSource: Send + Sync {
    /// Return exactly count entries (at most eight) from the specified offset.
    async fn page(&self, first: u32, count: u8) -> Result<Vec<TicketNoticeEntry>, StartupError>;
}
impl IssuerStartupSession {
    /// Revalidate the startup observation and stream the complete content-bound
    /// notice. Reconnect restarts at page zero. To refresh a still-uncommitted
    /// boot's predecessor hints, probe it again and supply a fresh snapshot for
    /// the same issuance; changed contents receive a new notice ID.
    pub async fn deliver_ticket_notice(
        mut self,
        notice: IssuedTicketNotice,
        source: &dyn TicketNoticeSource,
        deadline: tokio::time::Instant,
    ) -> Result<(), StartupError> {
        use super::{
            notice::{NoticeBoot, NoticeSequence},
            wire::FrameKind,
        };
        use tokio::io::AsyncWriteExt;
        if !self.proof.is_candidate() {
            return Err(StartupError::Invalid);
        }
        let boot = NoticeBoot {
            scope: self.proof.claims.scope.clone(),
            workload: self.proof.claims.workload,
            process: self.proof.claims.process,
            key: self.proof.boot_key_digest(),
        };
        let mut sequence = NoticeSequence::new(boot.clone());
        tokio::time::timeout_at(deadline, async {
            self.revalidate().await?;
            let notice_id = notice.id_for(&boot, source).await?;
            let mut first = 0;
            loop {
                self.revalidate().await?;
                let page = notice.page(&boot, notice_id, first, source).await?;
                let count = page.entries.len() as u32;
                let mut body = self.nonce.to_vec();
                body.extend_from_slice(&page.encode().map_err(|_| StartupError::Invalid)?);
                sequence
                    .accept_page(page)
                    .map_err(|_| StartupError::Invalid)?;
                self.revalidate().await?;
                let header = self
                    .header
                    .response(FrameKind::TicketNotice, body.len())
                    .map_err(|_| StartupError::Invalid)?;
                self.connection
                    .write_all(&header.encode().map_err(|_| StartupError::Invalid)?)
                    .await
                    .map_err(|_| StartupError::Unavailable)?;
                self.connection
                    .write_all(&body)
                    .await
                    .map_err(|_| StartupError::Unavailable)?;
                self.connection
                    .flush()
                    .await
                    .map_err(|_| StartupError::Unavailable)?;
                if sequence.is_complete() {
                    return Ok(());
                }
                first = first.checked_add(count).ok_or(StartupError::Invalid)?;
            }
        })
        .await
        .map_err(|_| StartupError::Unavailable)?
    }
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => { $(impl std::fmt::Debug for $ty {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(concat!(stringify!($ty), "([redacted])")) }
    })+ };
}
redacted_debug!(IssuedTicketNotice, TicketNoticeEntry);
