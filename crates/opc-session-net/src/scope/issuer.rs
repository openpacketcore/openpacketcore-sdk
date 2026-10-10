//! Issuer-side proof verification over an owned connection and independent Pod read.
use super::{
    clock::AuthenticationClock,
    credential::{
        BootstrapCredentialError, BootstrapCredentialVerifier, VerifiedBootstrapCredential,
    },
    platform::{KubernetesBootReader, PodEnrollment},
    pool::ProofBudgets,
    startup::StartupError,
};
use std::sync::Arc;
/// Distinct startup purposes; liveness never claims exclusion or admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapProofMode {
    /// Verify any independently observed boot at the exact workload UID.
    Liveness,
    /// Verify an excluded candidate with closed new-effect paths.
    Candidate,
}
/// Independently verified startup facts. This is not committed scope authority.
pub struct VerifiedBootstrapProof {
    pub(super) claims: super::proof::StartupClaims,
    observation: super::platform::RunningPodObservation,
    validity: VerifiedBootstrapCredential,
}
impl VerifiedBootstrapProof {
    /// Exact independently observed Pod UID.
    pub const fn workload(&self) -> &[u8; 16] {
        &self.claims.workload
    }
    /// Fresh worker process nonce proven with its boot key.
    pub const fn process_nonce(&self) -> &[u8; 16] {
        &self.claims.process
    }
    /// Commitment to the public boot key used on this connection.
    pub fn boot_key_digest(&self) -> [u8; 32] {
        super::wire::hash(&self.claims.public_key)
    }
    /// Whether the proof asserted the SDK's excluded candidate state.
    pub fn is_candidate(&self) -> bool {
        self.claims.mode == super::proof::StartupMode::Candidate
    }
    /// Exact public compressed P-256 key to bind into the durable issuer record.
    pub const fn public_key(&self) -> &[u8; 33] {
        &self.claims.public_key
    }
    /// Fixed scope proved on this connection.
    pub const fn scope(&self) -> &super::wire::ScopeBinding {
        &self.claims.scope
    }
}
impl std::fmt::Debug for VerifiedBootstrapProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedBootstrapProof([redacted])")
    }
}
/// A verified startup connection retained for ticket delivery after issuance.
pub struct IssuerStartupSession {
    pub(super) proof: VerifiedBootstrapProof,
    pub(super) connection: opc_tls::ScopeTlsConnection<tokio::net::TcpStream>,
    pub(super) header: super::wire::Header,
    pub(super) nonce: [u8; 32],
    enrollment: PodEnrollment,
    clock: Arc<dyn AuthenticationClock>,
    platform: Arc<KubernetesBootReader>,
}
impl IssuerStartupSession {
    /// Independently verified process facts; the raw credential is never returned.
    pub const fn proof(&self) -> &VerifiedBootstrapProof {
        &self.proof
    }
    /// Revalidate bootstrap JWT validity, the live connection and an exact Pod
    /// read before durable issuance. This never changes committed ownership.
    pub async fn revalidate(&self) -> Result<(), StartupError> {
        self.check_authentication()?;
        self.platform
            .revalidate(&self.enrollment, &self.proof.observation)
            .await
            .map_err(|_| StartupError::Unavailable)?;
        self.check_authentication()
    }
    fn check_authentication(&self) -> Result<(), StartupError> {
        let interval = self
            .clock
            .interval()
            .map_err(|_| StartupError::AuthTimeUnavailable)?;
        self.proof
            .validity
            .revalidate(interval)
            .map_err(credential_error)?;
        self.connection
            .channel_binding(self.proof.claims.mode.purpose(), interval)
            .map_err(|_| StartupError::AuthTimeUnavailable)?;
        Ok(())
    }
}
/// Configured issuer-side protocol client. Key discovery was preflighted already.
pub struct BootstrapIssuerClient {
    tls: opc_tls::AuthenticatedClientConfig,
    clock: Arc<dyn AuthenticationClock>,
    credentials: Arc<BootstrapCredentialVerifier>,
    platform: Arc<KubernetesBootReader>,
    proofs: super::pool::ProofPools,
}
impl BootstrapIssuerClient {
    /// Install constrained TLS, trusted time, activated keys and consistent reads.
    pub fn new(
        tls: opc_tls::AuthenticatedClientConfig,
        clock: Arc<dyn AuthenticationClock>,
        credentials: Arc<BootstrapCredentialVerifier>,
        platform: Arc<KubernetesBootReader>,
        budgets: ProofBudgets,
    ) -> Result<Self, StartupError> {
        tls.validate_scope_profile()
            .map_err(|_| StartupError::Invalid)?;
        let proofs = super::pool::ProofPools::new(budgets).map_err(|_| StartupError::Invalid)?;
        Ok(Self {
            tls,
            clock,
            credentials,
            platform,
            proofs,
        })
    }
    /// Freshly observe, connect, challenge and independently verify one startup.
    pub async fn probe(
        &self,
        enrollment: &PodEnrollment,
        mode: BootstrapProofMode,
    ) -> Result<IssuerStartupSession, StartupError> {
        use super::{
            pool::ProofShare,
            proof::{verify_signature, StartupClaims, StartupMode, StartupProof, StartupRequest},
            wire::*,
        };
        use std::time::Duration;
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            time::{timeout, Instant},
        };
        let observed = self
            .platform
            .observe(enrollment)
            .await
            .map_err(|_| StartupError::Unavailable)?;
        let handshake = self
            .tls
            .begin_handshake()
            .map_err(|_| StartupError::Unavailable)?;
        let mut connection = timeout(Duration::from_secs(5), async {
            let io = tokio::net::TcpStream::connect(observed.address())
                .await
                .map_err(|_| StartupError::Unavailable)?;
            handshake
                .connect_scope(
                    io,
                    enrollment
                        .scope
                        .tls_domain()
                        .map_err(|_| StartupError::Invalid)?,
                )
                .await
                .map_err(|_| StartupError::Unavailable)
        })
        .await
        .map_err(|_| StartupError::Unavailable)??;
        if connection.peer_identity().spiffe_id() != &enrollment.worker {
            return Err(StartupError::Unauthorized);
        }
        let mode = match mode {
            BootstrapProofMode::Liveness => StartupMode::Liveness,
            BootstrapProofMode::Candidate => StartupMode::Candidate,
        };
        connection
            .channel_binding(
                mode.purpose(),
                self.clock
                    .interval()
                    .map_err(|_| StartupError::AuthTimeUnavailable)?,
            )
            .map_err(|_| StartupError::AuthTimeUnavailable)?;
        let credit = self
            .proofs
            .reserve(
                Class::SafetyControl,
                ProofShare::Candidate,
                &enrollment.worker,
                enrollment.scope.commitment(),
            )
            .await
            .map_err(|_| StartupError::Unavailable)?;
        let (proof, header, nonce) = credit
            .with_challenge(Instant::now() + Duration::from_secs(5), |challenge| {
                let connection = &mut connection;
                async move {
                    Ok(async {
                        let id =
                            super::boot::random_nonzero().map_err(|_| StartupError::Unavailable)?;
                        let nonce =
                            super::boot::random_nonzero().map_err(|_| StartupError::Unavailable)?;
                        let request = StartupRequest {
                            scope: enrollment.scope.clone(),
                            workload: *observed.workload(),
                            observation: observed
                                .boot
                                .digest()
                                .map_err(|_| StartupError::Invalid)?,
                            challenge,
                        };
                        let payload = CallPayload {
                            nonce,
                            canonical: request.encode().map_err(|_| StartupError::Invalid)?,
                        };
                        let body = payload
                            .encode(mode.method())
                            .map_err(|_| StartupError::Invalid)?;
                        let header = Header {
                            kind: FrameKind::Call,
                            class: Class::SafetyControl,
                            method: mode.method(),
                            installation: *enrollment.scope.installation(),
                            scope: enrollment.scope.commitment(),
                            request_id: id,
                            digest: transport_request_digest(
                                mode.method(),
                                &id,
                                &payload.canonical,
                            )
                            .map_err(|_| StartupError::Invalid)?,
                            payload_len: body.len(),
                        };
                        connection
                            .write_all(&header.encode().map_err(|_| StartupError::Invalid)?)
                            .await
                            .map_err(|_| StartupError::Unavailable)?;
                        connection
                            .write_all(&body)
                            .await
                            .map_err(|_| StartupError::Unavailable)?;
                        connection
                            .flush()
                            .await
                            .map_err(|_| StartupError::Unavailable)?;
                        let mut fixed = [0; HEADER_BYTES];
                        connection
                            .read_exact(&mut fixed)
                            .await
                            .map_err(|_| StartupError::Unavailable)?;
                        let response = Header::decode(&fixed).map_err(|_| StartupError::Invalid)?;
                        if response.kind != FrameKind::Proof || !response.matches_attempt(&header) {
                            return Err(StartupError::Invalid);
                        }
                        let mut bytes = zeroize::Zeroizing::new(vec![0; response.payload_len]);
                        connection
                            .read_exact(&mut bytes)
                            .await
                            .map_err(|_| StartupError::Unavailable)?;
                        let proof =
                            StartupProof::decode(&bytes).map_err(|_| StartupError::Invalid)?;
                        let interval = self
                            .clock
                            .interval()
                            .map_err(|_| StartupError::AuthTimeUnavailable)?;
                        let binding = *connection
                            .channel_binding(mode.purpose(), interval)
                            .map_err(|_| StartupError::AuthTimeUnavailable)?
                            .as_bytes();
                        let claims = StartupClaims {
                            mode,
                            scope: enrollment.scope.clone(),
                            workload: request.workload,
                            process: proof.claims.process,
                            public_key: proof.claims.public_key,
                            credential_digest: hash(&proof.credential),
                            observation: request.observation,
                            challenge,
                            binding,
                        };
                        let input = claims.encode().map_err(|_| StartupError::Invalid)?;
                        if proof.claims.encode().map_err(|_| StartupError::Invalid)? != input {
                            return Err(StartupError::Unauthorized);
                        }
                        verify_signature(&claims.public_key, &input, &proof.signature)
                            .map_err(|_| StartupError::Unauthorized)?;
                        let validity = self
                            .credentials
                            .verify(&proof.credential, &observed.boot, interval)
                            .await
                            .map_err(credential_error)?;
                        self.platform
                            .revalidate(enrollment, &observed)
                            .await
                            .map_err(|_| StartupError::Unavailable)?;
                        let interval = self
                            .clock
                            .interval()
                            .map_err(|_| StartupError::AuthTimeUnavailable)?;
                        validity.revalidate(interval).map_err(credential_error)?;
                        connection
                            .channel_binding(mode.purpose(), interval)
                            .map_err(|_| StartupError::AuthTimeUnavailable)?;
                        Ok((
                            VerifiedBootstrapProof {
                                claims,
                                observation: observed,
                                validity,
                            },
                            header,
                            nonce,
                        ))
                    }
                    .await)
                }
            })
            .await
            .map_err(|_| StartupError::Unavailable)??;
        Ok(IssuerStartupSession {
            proof,
            connection,
            header,
            nonce,
            enrollment: enrollment.clone(),
            clock: self.clock.clone(),
            platform: self.platform.clone(),
        })
    }
}
fn credential_error(error: BootstrapCredentialError) -> StartupError {
    match error {
        BootstrapCredentialError::AuthTimeUnavailable => StartupError::AuthTimeUnavailable,
        BootstrapCredentialError::Rejected => StartupError::Unauthorized,
        BootstrapCredentialError::Unavailable
        | BootstrapCredentialError::UnsupportedPrerequisite => StartupError::Unavailable,
    }
}
