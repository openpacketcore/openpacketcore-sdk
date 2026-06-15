//! NETCONF-over-SSH listener.
//!
//! This module owns SSH accept/auth/subsystem handling only. The NETCONF
//! protocol still runs through the shared registry-aware session runner.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use opc_config_model::{OpcConfig, TransportType, TrustedPrincipal};
use opc_mgmt_audit::AuditSink;
use opc_mgmt_authz::PolicySource;
use opc_mgmt_limits::LimitsError;
use opc_runtime::ShutdownToken;
use opc_types::TenantId;
use russh::keys::{Certificate, PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, Disconnect, MethodKind, MethodSet, SshId};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, TryAcquireError};
use tokio::task::{JoinError, JoinSet};

use crate::binding::NetconfConfigBinding;
use crate::listener::allocate_session_id;
use crate::metrics::{active_session, TRANSPORT_NETCONF_SSH};
use crate::server::ReadOnlyNetconfServer;
use crate::session::SessionConfig;
use crate::session_registry::{is_valid_session_id, SessionRegistry};
use crate::transport::{run_read_only_ssh_session_with_registry, SshSessionError};

/// Host private key type consumed by the SSH listener.
pub type SshHostKey = PrivateKey;
/// Authorized client public key type consumed by the SSH listener.
pub type SshAuthorizedKey = PublicKey;

const NETCONF_SUBSYSTEM: &str = "netconf";

/// Runtime configuration for the NETCONF-over-SSH listener.
#[derive(Clone)]
pub struct SshListenerConfig {
    /// Per-session NETCONF protocol bounds and frame timeout.
    pub session: SessionConfig,
    /// First NETCONF session id assigned by this listener instance.
    pub first_session_id: u64,
    /// Maximum time to wait for in-flight sessions after shutdown begins.
    pub drain_timeout: Duration,
    /// Tenant assigned by trusted listener/operator policy.
    pub tenant: TenantId,
    /// Provisioned SSH host keys. At least one key is required.
    pub host_keys: Vec<SshHostKey>,
    /// Exact public keys allowed to authenticate to this listener.
    pub authorized_keys: Vec<SshAuthorizedKey>,
    /// Constant-time authentication rejection floor enforced by `russh`.
    pub auth_rejection_time: Duration,
    /// Optional rejection floor for the initial OpenSSH `none` probe.
    pub auth_rejection_time_initial: Option<Duration>,
    /// Maximum SSH authentication attempts per TCP connection.
    pub max_auth_attempts: usize,
    /// SSH connection inactivity timeout.
    pub inactivity_timeout: Option<Duration>,
    /// Optional SSH keepalive interval.
    pub keepalive_interval: Option<Duration>,
    /// Maximum unanswered SSH keepalives before disconnect.
    pub keepalive_max: usize,
}

impl SshListenerConfig {
    /// Builds a config from provisioned host keys and exact authorized keys.
    pub fn new(
        tenant: TenantId,
        host_keys: Vec<SshHostKey>,
        authorized_keys: Vec<SshAuthorizedKey>,
    ) -> Self {
        Self {
            session: SessionConfig::default(),
            first_session_id: 1,
            drain_timeout: Duration::from_secs(30),
            tenant,
            host_keys,
            authorized_keys,
            auth_rejection_time: Duration::from_secs(1),
            auth_rejection_time_initial: None,
            max_auth_attempts: 3,
            inactivity_timeout: Some(Duration::from_secs(600)),
            keepalive_interval: None,
            keepalive_max: 3,
        }
    }
}

impl std::fmt::Debug for SshListenerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshListenerConfig")
            .field("session", &self.session)
            .field("first_session_id", &self.first_session_id)
            .field("drain_timeout", &self.drain_timeout)
            .field("tenant", &self.tenant)
            .field(
                "host_keys",
                &format_args!("{} key(s)", self.host_keys.len()),
            )
            .field(
                "authorized_keys",
                &format_args!("{} key(s)", self.authorized_keys.len()),
            )
            .field("auth_rejection_time", &self.auth_rejection_time)
            .field(
                "auth_rejection_time_initial",
                &self.auth_rejection_time_initial,
            )
            .field("max_auth_attempts", &self.max_auth_attempts)
            .field("inactivity_timeout", &self.inactivity_timeout)
            .field("keepalive_interval", &self.keepalive_interval)
            .field("keepalive_max", &self.keepalive_max)
            .finish()
    }
}

/// Summary returned when the SSH listener stops.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SshListenerResult {
    /// TCP connections accepted and handed to an SSH/session worker.
    pub accepted_sessions: u64,
    /// Connections that authenticated, started `subsystem "netconf"`, and exited cleanly.
    pub completed_sessions: u64,
    /// Connections whose SSH auth, subsystem, NETCONF loop, join, or drain failed.
    pub failed_sessions: u64,
    /// Connections rejected because `MgmtLimits::max_sessions` or the session-id range was exhausted.
    pub rejected_sessions: u64,
}

/// Listener-level failure before the accept loop can run.
#[derive(Debug, Error)]
pub enum SshListenerError {
    /// Management-plane limits were invalid.
    #[error(transparent)]
    Limit(#[from] LimitsError),
    /// The configured first session id is outside the NETCONF session-id range.
    #[error("NETCONF SSH listener first session id is invalid")]
    InvalidFirstSessionId,
    /// The server was not constructed for NETCONF-over-SSH attribution.
    #[error("NETCONF SSH listener requires a NetconfSsh server transport")]
    WrongServerTransport {
        /// Transport currently recorded by the server.
        actual: TransportType,
    },
    /// No SSH host key was provisioned.
    #[error("NETCONF SSH listener requires at least one host key")]
    MissingHostKey,
    /// No authorized client public key was provisioned.
    #[error("NETCONF SSH listener requires at least one authorized public key")]
    MissingAuthorizedKey,
    /// SSH authentication attempt limit must be non-zero.
    #[error("NETCONF SSH listener max_auth_attempts must be non-zero")]
    InvalidAuthAttemptLimit,
    /// TCP accept failed.
    #[error("NETCONF SSH listener I/O error")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Error)]
enum SshWorkerError {
    #[error(transparent)]
    Ssh(#[from] russh::Error),
    #[error(transparent)]
    Session(#[from] SshSessionError),
    #[error("NETCONF SSH connection did not start the netconf subsystem")]
    NoNetconfSubsystem,
}

/// Runs a NETCONF-over-SSH listener until shutdown is requested.
///
/// The listener accepts public-key authentication only. Host keys and
/// authorized client keys must be provisioned by the caller; this function does
/// not generate keys, read user dotfiles, accept passwords, or infer tenancy
/// from usernames.
pub async fn run_read_only_ssh_listener<C, B, P, A>(
    server: Arc<ReadOnlyNetconfServer<C, B, P, A>>,
    listener: TcpListener,
    shutdown: ShutdownToken,
    config: SshListenerConfig,
) -> Result<SshListenerResult, SshListenerError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C> + 'static,
    P: PolicySource + 'static,
    A: AuditSink + 'static,
{
    run_read_only_ssh_listener_shared(server, Arc::new(listener), shutdown, config).await
}

pub(crate) async fn run_read_only_ssh_listener_shared<C, B, P, A>(
    server: Arc<ReadOnlyNetconfServer<C, B, P, A>>,
    listener: Arc<TcpListener>,
    shutdown: ShutdownToken,
    config: SshListenerConfig,
) -> Result<SshListenerResult, SshListenerError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C> + 'static,
    P: PolicySource + 'static,
    A: AuditSink + 'static,
{
    validate_listener_config(server.as_ref(), &config)?;
    let ssh_config = Arc::new(build_russh_config(&config));
    let auth_policy = Arc::new(SshAuthPolicy {
        tenant: config.tenant.clone(),
        authorized_keys: config.authorized_keys.clone(),
    });
    let semaphore = Arc::new(Semaphore::new(config.session.limits.max_sessions));
    let next_session_id = Arc::new(AtomicU64::new(config.first_session_id));
    let session_registry = SessionRegistry::new();
    let mut workers = JoinSet::new();
    let mut result = SshListenerResult::default();

    loop {
        tokio::select! {
            _ = shutdown.shutdown_acknowledged() => {
                break;
            }
            joined = workers.join_next(), if !workers.is_empty() => {
                if let Some(joined) = joined {
                    record_worker_result(joined, &mut result);
                }
            }
            accepted = listener.accept() => {
                let (stream, _peer) = accepted?;
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(TryAcquireError::NoPermits) => {
                        result.rejected_sessions = result.rejected_sessions.saturating_add(1);
                        tracing::debug!(
                            transport = TRANSPORT_NETCONF_SSH,
                            "NETCONF session rejected because max_sessions is reached"
                        );
                        continue;
                    }
                    Err(TryAcquireError::Closed) => break,
                };

                let Some(session_id) = allocate_session_id(&next_session_id) else {
                    result.rejected_sessions = result.rejected_sessions.saturating_add(1);
                    tracing::debug!(
                        transport = TRANSPORT_NETCONF_SSH,
                        "NETCONF session rejected because the session id range is exhausted"
                    );
                    continue;
                };

                let server = Arc::clone(&server);
                let ssh_config = Arc::clone(&ssh_config);
                let auth_policy = Arc::clone(&auth_policy);
                let session_config = config.session;
                let session_registry = session_registry.clone();
                result.accepted_sessions = result.accepted_sessions.saturating_add(1);

                workers.spawn(async move {
                    let _permit = permit;
                    let _active_session = active_session(TRANSPORT_NETCONF_SSH);
                    run_ssh_worker(
                        server,
                        ssh_config,
                        auth_policy,
                        stream,
                        session_config,
                        session_id,
                        session_registry,
                    )
                    .await
                });
            }
        }
    }

    drain_workers(&mut workers, config.drain_timeout, &mut result).await;
    Ok(result)
}

fn build_russh_config(config: &SshListenerConfig) -> server::Config {
    server::Config {
        server_id: SshId::Standard(Cow::Borrowed("SSH-2.0-openpacketcore-netconf")),
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        auth_rejection_time: config.auth_rejection_time,
        auth_rejection_time_initial: config.auth_rejection_time_initial,
        keys: config.host_keys.clone(),
        max_auth_attempts: config.max_auth_attempts,
        inactivity_timeout: config.inactivity_timeout,
        keepalive_interval: config.keepalive_interval,
        keepalive_max: config.keepalive_max,
        ..Default::default()
    }
}

async fn run_ssh_worker<C, B, P, A>(
    server: Arc<ReadOnlyNetconfServer<C, B, P, A>>,
    ssh_config: Arc<server::Config>,
    auth_policy: Arc<SshAuthPolicy>,
    stream: tokio::net::TcpStream,
    session_config: SessionConfig,
    session_id: u64,
    session_registry: SessionRegistry,
) -> Result<(), SshWorkerError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C> + 'static,
    P: PolicySource + 'static,
    A: AuditSink + 'static,
{
    let outcome = Arc::new(SshSessionOutcome::default());
    let handler = NetconfSshHandler {
        server,
        auth_policy,
        session_config,
        session_id,
        session_registry,
        principal: None,
        channels: HashMap::new(),
        outcome: Arc::clone(&outcome),
    };

    let running = server::run_stream(ssh_config, stream, handler).await?;
    running.await?;
    if outcome.failed.load(Ordering::Relaxed) {
        return Err(SshWorkerError::NoNetconfSubsystem);
    }
    if !outcome.started.load(Ordering::Relaxed) {
        return Err(SshWorkerError::NoNetconfSubsystem);
    }
    Ok(())
}

fn validate_listener_config<C, B, P, A>(
    server: &ReadOnlyNetconfServer<C, B, P, A>,
    config: &SshListenerConfig,
) -> Result<(), SshListenerError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
{
    config.session.limits.validate()?;
    if !is_valid_session_id(config.first_session_id) {
        return Err(SshListenerError::InvalidFirstSessionId);
    }
    let actual_transport = server.transport_type();
    if actual_transport != TransportType::NetconfSsh {
        return Err(SshListenerError::WrongServerTransport {
            actual: actual_transport,
        });
    }
    if config.host_keys.is_empty() {
        return Err(SshListenerError::MissingHostKey);
    }
    if config.authorized_keys.is_empty() {
        return Err(SshListenerError::MissingAuthorizedKey);
    }
    if config.max_auth_attempts == 0 {
        return Err(SshListenerError::InvalidAuthAttemptLimit);
    }
    Ok(())
}

async fn drain_workers(
    workers: &mut JoinSet<Result<(), SshWorkerError>>,
    timeout: Duration,
    result: &mut SshListenerResult,
) {
    let drain = async {
        while let Some(joined) = workers.join_next().await {
            record_worker_result(joined, result);
        }
    };

    if tokio::time::timeout(timeout, drain).await.is_err() {
        result.failed_sessions = result
            .failed_sessions
            .saturating_add(workers.len().try_into().unwrap_or(u64::MAX));
        workers.abort_all();
        while workers.join_next().await.is_some() {}
    }
}

fn record_worker_result(
    joined: Result<Result<(), SshWorkerError>, JoinError>,
    result: &mut SshListenerResult,
) {
    match joined {
        Ok(Ok(())) => {
            result.completed_sessions = result.completed_sessions.saturating_add(1);
        }
        Ok(Err(_)) | Err(_) => {
            result.failed_sessions = result.failed_sessions.saturating_add(1);
        }
    }
}

#[derive(Debug)]
struct SshAuthPolicy {
    tenant: TenantId,
    authorized_keys: Vec<SshAuthorizedKey>,
}

impl SshAuthPolicy {
    fn allows(&self, key: &PublicKey) -> bool {
        self.authorized_keys
            .iter()
            .any(|authorized| authorized.key_data() == key.key_data())
    }
}

#[derive(Debug, Default)]
struct SshSessionOutcome {
    started: AtomicBool,
    failed: AtomicBool,
}

struct NetconfSshHandler<C, B, P, A>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
{
    server: Arc<ReadOnlyNetconfServer<C, B, P, A>>,
    auth_policy: Arc<SshAuthPolicy>,
    session_config: SessionConfig,
    session_id: u64,
    session_registry: SessionRegistry,
    principal: Option<TrustedPrincipal>,
    channels: HashMap<ChannelId, Channel<Msg>>,
    outcome: Arc<SshSessionOutcome>,
}

impl<C, B, P, A> server::Handler for NetconfSshHandler<C, B, P, A>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C> + 'static,
    P: PolicySource + 'static,
    A: AuditSink + 'static,
{
    type Error = SshWorkerError;

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        if self.auth_policy.allows(public_key) {
            Ok(Auth::Accept)
        } else {
            Ok(reject_publickey())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        if !self.auth_policy.allows(public_key) {
            return Ok(reject_publickey());
        }
        match opc_mgmt_principal::principal_for_ssh_user(
            user.to_owned(),
            self.auth_policy.tenant.clone(),
        ) {
            Ok(principal) => {
                self.principal = Some(principal);
                Ok(Auth::Accept)
            }
            Err(err) => {
                tracing::debug!(error = %err, "rejected invalid SSH username");
                Ok(reject_publickey())
            }
        }
    }

    async fn auth_openssh_certificate(
        &mut self,
        _user: &str,
        _certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        Ok(reject_publickey())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if self.principal.is_none()
            || self.outcome.started.load(Ordering::Relaxed)
            || !self.channels.is_empty()
        {
            return Ok(false);
        }
        self.channels.insert(channel.id(), channel);
        Ok(true)
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != NETCONF_SUBSYSTEM || self.outcome.started.load(Ordering::Relaxed) {
            session.channel_failure(channel_id)?;
            return Ok(());
        }

        let Some(principal) = self.principal.clone() else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };
        let Some(channel) = self.channels.remove(&channel_id) else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };

        self.outcome.started.store(true, Ordering::Relaxed);
        session.channel_success(channel_id)?;

        let server = Arc::clone(&self.server);
        let session_config = self.session_config;
        let session_id = self.session_id;
        let session_registry = self.session_registry.clone();
        let outcome = Arc::clone(&self.outcome);
        let handle = session.handle();

        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let result = run_read_only_ssh_session_with_registry(
                server.as_ref(),
                &principal,
                &mut stream,
                session_config,
                session_id,
                &session_registry,
            )
            .await;
            if let Err(err) = result {
                outcome.failed.store(true, Ordering::Relaxed);
                tracing::debug!(error = %err, "NETCONF SSH subsystem session failed");
            }
            let _ = handle
                .disconnect(
                    Disconnect::ByApplication,
                    "NETCONF subsystem ended".to_string(),
                    "en".to_string(),
                )
                .await;
        });

        Ok(())
    }
}

fn reject_publickey() -> Auth {
    Auth::Reject {
        proceed_with_methods: Some(MethodSet::from(&[MethodKind::PublicKey][..])),
        partial_success: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_debug_redacts_host_key_material() {
        let host_key = PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("host key");
        let user_key = PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .expect("user key");
        let config = SshListenerConfig::new(
            TenantId::from_static("tenant-a"),
            vec![host_key],
            vec![user_key.public_key().clone()],
        );

        let debug = format!("{config:?}");
        assert!(debug.contains("1 key(s)"));
        assert!(!debug.contains("OPENSSH"));
    }
}
