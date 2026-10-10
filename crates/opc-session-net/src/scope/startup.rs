//! Restricted end-to-end bootstrap responder and process-owned exclusion.
use super::{
    boot::BootIdentity,
    clock::AuthenticationClock,
    lifecycle::{ScopeEffectPermit, ScopeGateError},
    policy::ScopePolicy,
    pool::ProofBudgets,
    wire::ScopeBinding,
};
use opc_types::SpiffeId;
use std::{fs::File, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;
/// Bounded bootstrap failure, with no credentials or proof bytes in diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StartupError {
    /// Invalid endpoint configuration, route or wire bytes.
    #[error("invalid scope startup input")]
    Invalid,
    /// The old local process still holds its exclusion lock; retry automatically.
    #[error("scope startup exclusion busy")]
    ExclusionBusy,
    /// The authenticated issuer is no longer authorized for this exact scope.
    #[error("scope startup issuer unauthorized")]
    Unauthorized,
    /// A bounded I/O attempt or trusted source is temporarily unavailable.
    #[error("scope startup unavailable")]
    Unavailable,
    /// No complete current authentication interval is available.
    #[error("scope startup authentication time unavailable")]
    AuthTimeUnavailable,
    /// Local effect or process-protection conditions no longer permit the proof.
    #[error("scope startup gate closed")]
    GateClosed,
}
/// Confidential projected credential, kept out of diagnostic and serialization APIs.
pub struct BootstrapCredential(Zeroizing<Vec<u8>>);
impl BootstrapCredential {
    /// Validate the bounded ASCII token returned by a trusted projected-file source.
    pub fn new(bytes: Vec<u8>) -> Result<Self, StartupError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty()
            || bytes.len() > 4096
            || !bytes.is_ascii()
            || bytes.iter().any(|c| c.is_ascii_control() || *c == b' ')
        {
            return Err(StartupError::Invalid);
        }
        Ok(Self(bytes))
    }
}
/// Trusted worker-only projected token mount; read a fresh value for each proof.
#[async_trait::async_trait]
pub trait BootstrapCredentialSource: Send + Sync {
    /// Called only after the live connection authenticates the configured issuer.
    async fn read(&self) -> Result<BootstrapCredential, StartupError>;
}
/// One boot, one exact local scope, and the exclusion lock held for its lifetime.
pub struct ScopeProcess {
    pub(super) scope: ScopeBinding,
    pub(super) workload: [u8; 16],
    pub(super) boot: BootIdentity,
    pub(super) gate: super::lifecycle::EffectGate,
    _lock: File,
}
impl ScopeProcess {
    /// Acquire the SDK's scope lock in an already trusted local directory.
    /// A busy predecessor is retryable; the OS releases its lock on process exit.
    pub fn new(
        scope: ScopeBinding,
        workload: [u8; 16],
        boot: BootIdentity,
        directory: File,
    ) -> Result<Self, StartupError> {
        if workload == [0; 16]
            || !directory
                .metadata()
                .map_err(|_| StartupError::Invalid)?
                .is_dir()
        {
            return Err(StartupError::Invalid);
        }
        boot.check_protection()
            .map_err(|_| StartupError::GateClosed)?;
        #[cfg(target_os = "linux")]
        let lock = {
            use rustix::fs::{flock, openat, FlockOperation, Mode, OFlags};
            let name = scope
                .commitment()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let fd = openat(
                &directory,
                format!("opc-scope-{name}.lock"),
                OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| StartupError::Unavailable)?;
            let lock = File::from(fd);
            if !lock
                .metadata()
                .map_err(|_| StartupError::Unavailable)?
                .is_file()
            {
                return Err(StartupError::Invalid);
            }
            flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
                if error == rustix::io::Errno::WOULDBLOCK {
                    StartupError::ExclusionBusy
                } else {
                    StartupError::Unavailable
                }
            })?;
            lock
        };
        #[cfg(not(target_os = "linux"))]
        let lock = {
            let _ = scope;
            return Err(StartupError::Unavailable);
            #[allow(unreachable_code)]
            directory
        };
        Ok(Self {
            scope,
            workload,
            boot,
            gate: super::lifecycle::EffectGate::new(),
            _lock: lock,
        })
    }
    /// Public boot identity; the key has no export or arbitrary signing method.
    pub const fn boot(&self) -> &BootIdentity {
        &self.boot
    }
    /// Fixed local scope; no reconnect changes this binding.
    pub const fn scope(&self) -> &ScopeBinding {
        &self.scope
    }
    /// Admit a peer-control submission only while this boot is active.
    pub async fn enter_peer_control(&self) -> Result<ScopeEffectPermit, ScopeGateError> {
        self.boot.check_protection().map_err(|_| ScopeGateError)?;
        self.gate.enter().await
    }
}
impl std::fmt::Debug for ScopeProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScopeProcess([redacted])")
    }
}
impl std::fmt::Debug for BootstrapCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BootstrapCredential([redacted])")
    }
}
/// A configured token projection, opened afresh to follow kubelet rotation.
pub struct ProjectedBootstrapToken {
    path: std::path::PathBuf,
}
impl ProjectedBootstrapToken {
    /// Install the trusted worker-only projected-file path, independent of peers.
    pub fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }
}
#[async_trait::async_trait]
impl BootstrapCredentialSource for ProjectedBootstrapToken {
    async fn read(&self) -> Result<BootstrapCredential, StartupError> {
        use tokio::io::AsyncReadExt;
        let file = tokio::fs::File::open(&self.path)
            .await
            .map_err(|_| StartupError::Unavailable)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(4097));
        file.take(4097)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| StartupError::Unavailable)?;
        BootstrapCredential::new(std::mem::take(&mut *bytes))
    }
}
/// Startup listener restricted to a configured issuer and exact worker scope.
pub struct BootProofResponder {
    process: Arc<ScopeProcess>,
    issuer: SpiffeId,
    policy: ScopePolicy,
    clock: Arc<dyn AuthenticationClock>,
    credential: Arc<dyn BootstrapCredentialSource>,
    tls: opc_tls::AuthenticatedServerConfig,
    proofs: super::pool::ProofPools,
    handshakes: tokio::sync::Semaphore,
}
impl BootProofResponder {
    /// Validate the TLS profile and all reserved budgets before serving.
    pub fn new(
        process: Arc<ScopeProcess>,
        issuer: SpiffeId,
        policy: ScopePolicy,
        clock: Arc<dyn AuthenticationClock>,
        credential: Arc<dyn BootstrapCredentialSource>,
        tls: opc_tls::AuthenticatedServerConfig,
        budgets: ProofBudgets,
    ) -> Result<Self, StartupError> {
        tls.validate_scope_profile()
            .map_err(|_| StartupError::Invalid)?;
        let proofs = super::pool::ProofPools::new(budgets).map_err(|_| StartupError::Invalid)?;
        Ok(Self {
            process,
            issuer,
            policy,
            clock,
            credential,
            tls,
            proofs,
            handshakes: tokio::sync::Semaphore::new(8),
        })
    }
    /// Perform one bounded proof exchange on a fresh stream, beginning with mTLS.
    /// The returned connection may receive a correlated ticket notice.
    pub async fn respond_once<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: S,
    ) -> Result<StartupSession<S>, StartupError> {
        use super::{
            pool::ProofShare,
            proof::{StartupMode, StartupRequest},
            wire::*,
        };
        use std::time::Duration;
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            time::{timeout, Instant},
        };
        let handshake_credit = self
            .handshakes
            .acquire()
            .await
            .map_err(|_| StartupError::Unavailable)?;
        let handshake = self
            .tls
            .begin_handshake()
            .map_err(|_| StartupError::Unavailable)?;
        let (mut connection, header) = timeout(Duration::from_secs(5), async {
            let mut stream = handshake
                .accept_scope_unbound(io)
                .await
                .map_err(|_| StartupError::Unavailable)?;
            let mut fixed = [0; HEADER_BYTES];
            stream
                .read_exact(&mut fixed)
                .await
                .map_err(|_| StartupError::Unavailable)?;
            let header = Header::decode(&fixed).map_err(|_| StartupError::Invalid)?;
            if header.kind != FrameKind::Call
                || header.installation != *self.process.scope.installation()
                || header.scope != self.process.scope.commitment()
            {
                return Err(StartupError::Invalid);
            }
            let stream = stream
                .bind_scope(
                    self.process
                        .scope
                        .tls_domain()
                        .map_err(|_| StartupError::Invalid)?,
                )
                .map_err(|_| StartupError::Invalid)?;
            Ok((stream, header))
        })
        .await
        .map_err(|_| StartupError::Unavailable)??;
        drop(handshake_credit);
        let route = self
            .policy
            .authorize_startup(
                connection.peer_identity().spiffe_id(),
                &self.issuer,
                &self.process.scope,
                header.method,
                header.class,
            )
            .map_err(|_| StartupError::Unauthorized)?;
        let credit = self
            .proofs
            .reserve(
                header.class,
                ProofShare::Controller,
                &route.principal,
                route.scope.commitment(),
            )
            .await
            .map_err(|_| StartupError::Unavailable)?;
        let nonce = credit
            .with_challenge(Instant::now() + Duration::from_secs(5), |_| async {
                Ok(async {
                    route.revalidate().map_err(|_| StartupError::Unauthorized)?;
                    let mode = match header.method {
                        Method::Liveness => StartupMode::Liveness,
                        Method::Candidate => StartupMode::Candidate,
                        _ => return Err(StartupError::Invalid),
                    };
                    connection
                        .channel_binding(
                            mode.purpose(),
                            self.clock
                                .interval()
                                .map_err(|_| StartupError::AuthTimeUnavailable)?,
                        )
                        .map_err(|_| StartupError::AuthTimeUnavailable)?;
                    let mut body = vec![0; header.payload_len];
                    connection
                        .read_exact(&mut body)
                        .await
                        .map_err(|_| StartupError::Unavailable)?;
                    let payload = CallPayload::decode(header.method, &body)
                        .map_err(|_| StartupError::Invalid)?;
                    if transport_request_digest(
                        header.method,
                        &header.request_id,
                        &payload.canonical,
                    )
                    .map_err(|_| StartupError::Invalid)?
                        != header.digest
                    {
                        return Err(StartupError::Invalid);
                    }
                    let request = StartupRequest::decode(&payload.canonical)
                        .map_err(|_| StartupError::Invalid)?;
                    if request.scope != self.process.scope
                        || request.workload != self.process.workload
                    {
                        return Err(StartupError::Invalid);
                    }
                    let candidate = if mode == StartupMode::Candidate {
                        Some(
                            self.process
                                .gate
                                .candidate()
                                .await
                                .map_err(|_| StartupError::GateClosed)?,
                        )
                    } else {
                        None
                    };
                    let mut credential = self.credential.read().await?;
                    route.revalidate().map_err(|_| StartupError::Unauthorized)?;
                    let proof = self.process.boot.startup_proof(
                        &connection,
                        self.clock
                            .interval()
                            .map_err(|_| StartupError::AuthTimeUnavailable)?,
                        &request,
                        mode,
                        std::mem::take(&mut *credential.0),
                        candidate.as_ref(),
                    )?;
                    let bytes = Zeroizing::new(proof.encode().map_err(|_| StartupError::Invalid)?);
                    let reply = header
                        .response(FrameKind::Proof, bytes.len())
                        .map_err(|_| StartupError::Invalid)?;
                    connection
                        .write_all(&reply.encode().map_err(|_| StartupError::Invalid)?)
                        .await
                        .map_err(|_| StartupError::Unavailable)?;
                    connection
                        .write_all(&bytes)
                        .await
                        .map_err(|_| StartupError::Unavailable)?;
                    connection
                        .flush()
                        .await
                        .map_err(|_| StartupError::Unavailable)?;
                    drop(candidate);
                    Ok(payload.nonce)
                }
                .await)
            })
            .await
            .map_err(|_| StartupError::Unavailable)??;
        Ok(StartupSession {
            connection,
            header,
            nonce,
            route,
            clock: self.clock.clone(),
            process: self.process.clone(),
        })
    }
}
/// One completed startup proof, retained only for the issuer's ticket notice.
pub struct StartupSession<S> {
    connection: opc_tls::ScopeTlsConnection<S>,
    header: super::wire::Header,
    nonce: [u8; 32],
    route: super::policy::RoutedCall,
    clock: Arc<dyn AuthenticationClock>,
    process: Arc<ScopeProcess>,
}

/// Issuer-delivered hints for this exact boot; admission reads authority again.
#[derive(Clone)]
pub struct BootTicket {
    pub(super) hint: super::notice::TicketHint,
}
impl BootTicket {
    /// Accept hints returned by a configured issuer read port for this exact boot.
    /// This does not verify issuance or confer authority; the quorum reads again.
    pub fn from_authority_record(
        process: &ScopeProcess,
        record: &super::evidence::BootAuthorityRecord,
    ) -> Result<Self, StartupError> {
        if record.scope != process.scope
            || record.execution.workload() != &process.workload
            || record.execution.process() != process.boot.process_nonce()
            || record.execution.boot_key() != &process.boot.key_digest()
            || record.public_key != *process.boot.public_key()
        {
            return Err(StartupError::Invalid);
        }
        let boot = super::notice::NoticeBoot {
            scope: process.scope.clone(),
            workload: process.workload,
            process: *process.boot.process_nonce(),
            key: process.boot.key_digest(),
        };
        let notice = super::IssuedTicketNotice {
            generation: record.execution.admission_generation(),
            authority: record.reference.clone(),
            total_predecessors: 0,
        };
        Ok(Self {
            hint: super::notice::TicketHint {
                notice_id: super::notice::NoticeCommitment::new(
                    &boot,
                    notice.generation,
                    &notice.authority,
                    0,
                )
                .and_then(super::notice::NoticeCommitment::finish)
                .map_err(|_| StartupError::Invalid)?,
                boot,
                generation: notice.generation,
                authority: notice.authority,
            },
        })
    }
    /// Issued generation, never proof of committed ownership.
    pub const fn generation(&self) -> u64 {
        self.hint.generation
    }
    /// Content commitment for this complete evidence snapshot. Equal redeliveries
    /// keep the ID; a refreshed snapshot can change it without changing issuance.
    /// IDs have no time order and confer no authority.
    pub const fn notice_id(&self) -> &[u8; 16] {
        &self.hint.notice_id
    }
    /// Immutable authority record identifier, treated as opaque bytes.
    pub fn authority_record_uid(&self) -> &[u8] {
        &self.hint.authority.record_uid
    }
    /// Opaque equality-only revision used to independently revalidate issuance.
    pub fn authority_revision(&self) -> &[u8] {
        &self.hint.authority.revision
    }
}
impl std::fmt::Debug for BootTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BootTicket([redacted])")
    }
}
/// One bounded predecessor hint. It has not verified predecessor closure.
pub struct ClosureNotice {
    pub(super) hint: super::notice::ClosureHint,
}
impl ClosureNotice {
    /// Canonical native predecessor stamp claim; decode and validate before use.
    pub fn predecessor_bytes(&self) -> &[u8] {
        &self.hint.predecessor
    }
    /// Immutable evidence commitment, independently verified during admission.
    pub const fn evidence_digest(&self) -> &[u8; 32] {
        &self.hint.digest
    }
    /// Typed closure claim to cite after resolving the actual predecessor.
    /// Admission independently verifies this claim; receiving it grants no authority.
    pub fn evidence(
        &self,
    ) -> Result<opc_session_store::scope_authority::ScopeClosureEvidence, StartupError> {
        use opc_session_store::scope_authority::{ScopeClosureEvidence, ScopeClosureKind};
        let kind = match (self.hint.kind, self.hint.record.is_some()) {
            (1, true) => ScopeClosureKind::FinalTermination,
            (2, false) => ScopeClosureKind::CommittedClose,
            _ => return Err(StartupError::Invalid),
        };
        ScopeClosureEvidence::new(kind, self.hint.digest).map_err(|_| StartupError::Invalid)
    }
    /// Immutable record UID and opaque revision for a final-termination hint.
    /// These identify a record for a trusted reader; they do not verify its contents.
    pub fn record_reference(&self) -> Option<(&[u8], &[u8])> {
        self.hint
            .record
            .as_ref()
            .map(|record| (record.record_uid.as_slice(), record.revision.as_slice()))
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> StartupSession<S> {
    /// Receive all correlated pages, streaming predecessor hints without retaining
    /// an unbounded list. A ticket becomes usable only after the full content
    /// commitment is checked. Stage hints until this call succeeds; discard a
    /// partial or invalid set. A fresh startup exchange can replace the hints for
    /// the same issuance with a later complete snapshot, without a new generation.
    pub async fn receive_ticket_notice<F>(
        mut self,
        deadline: tokio::time::Instant,
        mut hint: F,
    ) -> Result<BootTicket, StartupError>
    where
        F: FnMut(ClosureNotice) -> Result<(), StartupError>,
    {
        use super::{
            notice::{NoticeBoot, NoticePage, NoticeSequence},
            wire::*,
        };
        use tokio::io::AsyncReadExt;
        if self.header.method != Method::Candidate {
            return Err(StartupError::Invalid);
        }
        let mut sequence = NoticeSequence::new(NoticeBoot {
            scope: self.process.scope.clone(),
            workload: self.process.workload,
            process: *self.process.boot.process_nonce(),
            key: self.process.boot.key_digest(),
        });
        tokio::time::timeout_at(deadline, async {
            loop {
                self.route
                    .revalidate()
                    .map_err(|_| StartupError::Unauthorized)?;
                self.connection
                    .channel_binding(
                        opc_tls::ChannelBindingPurpose::BootCandidate,
                        self.clock
                            .interval()
                            .map_err(|_| StartupError::AuthTimeUnavailable)?,
                    )
                    .map_err(|_| StartupError::AuthTimeUnavailable)?;
                let mut fixed = [0; HEADER_BYTES];
                self.connection
                    .read_exact(&mut fixed)
                    .await
                    .map_err(|_| StartupError::Unavailable)?;
                let header = Header::decode(&fixed).map_err(|_| StartupError::Invalid)?;
                if header.kind != FrameKind::TicketNotice || !header.matches_attempt(&self.header) {
                    return Err(StartupError::Invalid);
                }
                let mut body = vec![0; header.payload_len];
                self.connection
                    .read_exact(&mut body)
                    .await
                    .map_err(|_| StartupError::Unavailable)?;
                if body.get(..32) != Some(self.nonce.as_slice()) {
                    return Err(StartupError::Invalid);
                }
                let page = NoticePage::decode(body.get(32..).ok_or(StartupError::Invalid)?)
                    .map_err(|_| StartupError::Invalid)?;
                self.route
                    .revalidate()
                    .map_err(|_| StartupError::Unauthorized)?;
                self.connection
                    .channel_binding(
                        opc_tls::ChannelBindingPurpose::BootCandidate,
                        self.clock
                            .interval()
                            .map_err(|_| StartupError::AuthTimeUnavailable)?,
                    )
                    .map_err(|_| StartupError::AuthTimeUnavailable)?;
                let entries = sequence
                    .accept_page(page)
                    .map_err(|_| StartupError::Invalid)?;
                for entry in entries {
                    hint(ClosureNotice { hint: entry })?;
                }
                if let Some(ticket) = sequence.ticket() {
                    return Ok(BootTicket {
                        hint: ticket.clone(),
                    });
                }
            }
        })
        .await
        .map_err(|_| StartupError::Unavailable)?
    }
}
