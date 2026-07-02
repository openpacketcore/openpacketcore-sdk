//! NETCONF-over-SSH listener.
//!
//! This module owns SSH accept/auth/subsystem handling only. The NETCONF
//! protocol still runs through the shared registry-aware session runner.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use opc_config_model::{OpcConfig, TransportType, TrustedPrincipal};
use opc_mgmt_audit::AuditSink;
use opc_mgmt_authz::PolicySource;
use opc_mgmt_limits::LimitsError;
use opc_runtime::ShutdownToken;
use opc_types::TenantId;
use russh::keys::{self, Certificate, PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId, Disconnect, MethodKind, MethodSet, SshId};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, TryAcquireError};
use tokio::task::{JoinError, JoinHandle, JoinSet};

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
const CALL_HOME_BACKOFF_JITTER_DIVISOR: u128 = 4;

/// SSH key material loaded from deployment-managed files.
#[derive(Clone)]
pub struct SshListenerKeyMaterial {
    /// Provisioned SSH host keys.
    pub host_keys: Vec<SshHostKey>,
    /// Exact public keys allowed to authenticate to this listener.
    pub authorized_keys: Vec<SshAuthorizedKey>,
}

impl std::fmt::Debug for SshListenerKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshListenerKeyMaterial")
            .field(
                "host_keys",
                &format_args!("{} key(s)", self.host_keys.len()),
            )
            .field(
                "authorized_keys",
                &format_args!("{} key(s)", self.authorized_keys.len()),
            )
            .finish()
    }
}

/// Redaction-safe SSH key file loader error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SshKeyFileLoadError {
    /// No host-key path was provided.
    #[error("netconf_ssh_host_key_path_missing")]
    HostKeyPathMissing,
    /// A host-key file could not be read.
    #[error("netconf_ssh_host_key_read_error")]
    HostKeyRead {
        /// Zero-based host-key file index.
        index: usize,
    },
    /// A host-key file contained no key material.
    #[error("netconf_ssh_host_key_empty")]
    HostKeyEmpty {
        /// Zero-based host-key file index.
        index: usize,
    },
    /// A host-key file contained unsupported, encrypted, or malformed key material.
    #[error("netconf_ssh_host_key_invalid")]
    HostKeyInvalid {
        /// Zero-based host-key file index.
        index: usize,
    },
    /// Authorized-keys file could not be read.
    #[error("netconf_ssh_authorized_keys_read_error")]
    AuthorizedKeysRead,
    /// Authorized-keys file contained no bytes or only whitespace.
    #[error("netconf_ssh_authorized_keys_empty")]
    AuthorizedKeysEmpty,
    /// Authorized-keys file contained only comments or blank lines.
    #[error("netconf_ssh_authorized_keys_no_records")]
    AuthorizedKeysNoRecords,
    /// Authorized-keys file contained an invalid public-key record.
    #[error("netconf_ssh_authorized_key_invalid")]
    AuthorizedKeyInvalid {
        /// One-based line number of the invalid record.
        line: usize,
    },
    /// Authorized-keys file repeated a public key already loaded from an earlier line.
    #[error("netconf_ssh_authorized_key_duplicate")]
    AuthorizedKeyDuplicate {
        /// One-based line number of the duplicate record.
        line: usize,
    },
}

impl SshKeyFileLoadError {
    /// Return the stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostKeyPathMissing => "netconf_ssh_host_key_path_missing",
            Self::HostKeyRead { .. } => "netconf_ssh_host_key_read_error",
            Self::HostKeyEmpty { .. } => "netconf_ssh_host_key_empty",
            Self::HostKeyInvalid { .. } => "netconf_ssh_host_key_invalid",
            Self::AuthorizedKeysRead => "netconf_ssh_authorized_keys_read_error",
            Self::AuthorizedKeysEmpty => "netconf_ssh_authorized_keys_empty",
            Self::AuthorizedKeysNoRecords => "netconf_ssh_authorized_keys_no_records",
            Self::AuthorizedKeyInvalid { .. } => "netconf_ssh_authorized_key_invalid",
            Self::AuthorizedKeyDuplicate { .. } => "netconf_ssh_authorized_key_duplicate",
        }
    }
}

/// Load NETCONF SSH listener key material from deployment-managed files.
///
/// Host-key files must contain unencrypted private keys supported by `russh`.
/// The authorized-keys file accepts ordinary OpenSSH public-key records, skips
/// blank/comment lines, and preserves exact public-key authorization semantics
/// used by [`SshListenerConfig`].
///
/// # Errors
///
/// Returns [`SshKeyFileLoadError`] when a file cannot be read, contains no
/// usable records, has unsupported key material, or repeats an authorized key.
pub fn load_ssh_listener_key_files<H, P>(
    host_key_paths: H,
    authorized_keys_path: P,
) -> Result<SshListenerKeyMaterial, SshKeyFileLoadError>
where
    H: IntoIterator,
    H::Item: AsRef<Path>,
    P: AsRef<Path>,
{
    let mut host_keys = Vec::new();
    let mut saw_host_path = false;
    for (index, path) in host_key_paths.into_iter().enumerate() {
        saw_host_path = true;
        host_keys.push(load_host_key_file(path.as_ref(), index)?);
    }
    if !saw_host_path {
        return Err(SshKeyFileLoadError::HostKeyPathMissing);
    }

    let authorized_keys = load_authorized_keys_file(authorized_keys_path.as_ref())?;
    Ok(SshListenerKeyMaterial {
        host_keys,
        authorized_keys,
    })
}

fn load_host_key_file(path: &Path, index: usize) -> Result<SshHostKey, SshKeyFileLoadError> {
    let contents =
        fs::read_to_string(path).map_err(|_| SshKeyFileLoadError::HostKeyRead { index })?;
    if contents.trim().is_empty() {
        return Err(SshKeyFileLoadError::HostKeyEmpty { index });
    }
    keys::decode_secret_key(&contents, None)
        .map_err(|_| SshKeyFileLoadError::HostKeyInvalid { index })
}

fn load_authorized_keys_file(path: &Path) -> Result<Vec<SshAuthorizedKey>, SshKeyFileLoadError> {
    let contents = fs::read_to_string(path).map_err(|_| SshKeyFileLoadError::AuthorizedKeysRead)?;
    if contents.trim().is_empty() {
        return Err(SshKeyFileLoadError::AuthorizedKeysEmpty);
    }

    let mut authorized_keys = Vec::new();
    let mut saw_record = false;
    for (line_index, line) in contents.lines().enumerate() {
        let line_number = line_index.saturating_add(1);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        saw_record = true;
        let key = parse_authorized_key_record(trimmed, line_number)?;
        if authorized_keys
            .iter()
            .any(|existing: &SshAuthorizedKey| existing.key_data() == key.key_data())
        {
            return Err(SshKeyFileLoadError::AuthorizedKeyDuplicate { line: line_number });
        }
        authorized_keys.push(key);
    }

    if saw_record {
        Ok(authorized_keys)
    } else {
        Err(SshKeyFileLoadError::AuthorizedKeysNoRecords)
    }
}

fn parse_authorized_key_record(
    record: &str,
    line: usize,
) -> Result<SshAuthorizedKey, SshKeyFileLoadError> {
    let tokens: Vec<&str> = record.split_whitespace().collect();
    let Some(key_blob) = authorized_key_blob(&tokens) else {
        return Err(SshKeyFileLoadError::AuthorizedKeyInvalid { line });
    };
    keys::parse_public_key_base64(key_blob)
        .map_err(|_| SshKeyFileLoadError::AuthorizedKeyInvalid { line })
}

fn authorized_key_blob<'a>(tokens: &'a [&str]) -> Option<&'a str> {
    if tokens.len() == 1 {
        return tokens.first().copied();
    }

    tokens
        .windows(2)
        .find_map(|window| is_public_key_algorithm(window[0]).then_some(window[1]))
        .or_else(|| tokens.first().copied())
}

fn is_public_key_algorithm(token: &str) -> bool {
    token == "ssh-ed25519"
        || token == "ssh-rsa"
        || token == "rsa-sha2-256"
        || token == "rsa-sha2-512"
        || token.starts_with("ecdsa-sha2-")
        || token.starts_with("sk-")
}

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

/// Runtime configuration for NETCONF-over-SSH Call Home.
#[derive(Debug, Clone)]
pub struct SshCallHomeConfig {
    /// SSH/NETCONF server-side policy used after the outbound TCP connection is established.
    pub ssh: SshListenerConfig,
    /// NMS endpoints to dial. The runner tries them round-robin.
    pub endpoints: Vec<SocketAddr>,
    /// Maximum time allowed for one outbound TCP connect attempt.
    pub connect_timeout: Duration,
    /// Initial reconnect backoff after a failed connect/session attempt.
    pub retry_initial: Duration,
    /// Maximum reconnect backoff.
    pub retry_max: Duration,
}

impl SshCallHomeConfig {
    /// Builds a Call Home config from an SSH server policy and NMS endpoints.
    pub fn new(ssh: SshListenerConfig, endpoints: Vec<SocketAddr>) -> Self {
        Self {
            ssh,
            endpoints,
            connect_timeout: Duration::from_secs(10),
            retry_initial: Duration::from_secs(1),
            retry_max: Duration::from_secs(60),
        }
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

/// Summary returned when the SSH Call Home runner stops.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SshCallHomeResult {
    /// Outbound TCP connection attempts.
    pub connection_attempts: u64,
    /// Outbound TCP connections handed to SSH/session handling.
    pub connected_sessions: u64,
    /// Connections that authenticated, started `subsystem "netconf"`, and exited cleanly.
    pub completed_sessions: u64,
    /// TCP connect attempts that failed or timed out before SSH started.
    pub connection_failures: u64,
    /// Connections whose SSH auth, subsystem, NETCONF loop, join, or drain failed.
    pub failed_sessions: u64,
    /// Connections rejected because the session-id range was exhausted.
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

/// Call Home configuration failure before the outbound connection loop can run.
#[derive(Debug, Error)]
pub enum SshCallHomeError {
    /// Shared SSH server-side policy was invalid.
    #[error(transparent)]
    Listener(#[from] SshListenerError),
    /// No NMS endpoint was configured.
    #[error("NETCONF SSH Call Home requires at least one endpoint")]
    MissingEndpoint,
    /// Outbound TCP connect timeout must be non-zero.
    #[error("NETCONF SSH Call Home connect_timeout must be non-zero")]
    InvalidConnectTimeout,
    /// Retry backoff bounds must be non-zero and ordered.
    #[error("NETCONF SSH Call Home retry backoff must be non-zero and retry_max >= retry_initial")]
    InvalidRetryBackoff,
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

/// Runs NETCONF-over-SSH Call Home until shutdown is requested.
///
/// The TCP connection is initiated outbound to one of the configured NMS
/// endpoints, but this side still runs the SSH server role and accepts only
/// public-key authentication plus `subsystem "netconf"`. Reconnect attempts are
/// bounded by exponential backoff with deterministic jitter so a broken NMS
/// cannot create a tight loop.
pub async fn run_read_only_ssh_call_home<C, B, P, A>(
    server: Arc<ReadOnlyNetconfServer<C, B, P, A>>,
    shutdown: ShutdownToken,
    config: SshCallHomeConfig,
) -> Result<SshCallHomeResult, SshCallHomeError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C> + 'static,
    P: PolicySource + 'static,
    A: AuditSink + 'static,
{
    validate_call_home_config(server.as_ref(), &config)?;
    let ssh_config = Arc::new(build_russh_config(&config.ssh));
    let auth_policy = Arc::new(SshAuthPolicy {
        tenant: config.ssh.tenant.clone(),
        authorized_keys: config.ssh.authorized_keys.clone(),
    });
    let next_session_id = Arc::new(AtomicU64::new(config.ssh.first_session_id));
    let session_registry = SessionRegistry::new();
    let mut result = SshCallHomeResult::default();
    let mut endpoint_index = 0usize;
    let mut attempt = 0u64;
    let mut retry = config.retry_initial;

    loop {
        let endpoint = config.endpoints[endpoint_index];
        endpoint_index = (endpoint_index + 1) % config.endpoints.len();
        result.connection_attempts = result.connection_attempts.saturating_add(1);

        let connect = tokio::time::timeout(config.connect_timeout, TcpStream::connect(endpoint));
        let stream = tokio::select! {
            _ = shutdown.shutdown_acknowledged() => break,
            connected = connect => connected,
        };

        let stream = match stream {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                result.connection_failures = result.connection_failures.saturating_add(1);
                tracing::debug!(
                    transport = TRANSPORT_NETCONF_SSH,
                    endpoint = %endpoint,
                    error = %err,
                    "NETCONF SSH Call Home connect failed"
                );
                let wait = deterministic_jitter(retry, attempt, endpoint_index);
                if sleep_or_shutdown(wait, &shutdown).await {
                    break;
                }
                retry = next_backoff(retry, config.retry_max);
                attempt = attempt.saturating_add(1);
                continue;
            }
            Err(_) => {
                result.connection_failures = result.connection_failures.saturating_add(1);
                tracing::debug!(
                    transport = TRANSPORT_NETCONF_SSH,
                    endpoint = %endpoint,
                    "NETCONF SSH Call Home connect timed out"
                );
                let wait = deterministic_jitter(retry, attempt, endpoint_index);
                if sleep_or_shutdown(wait, &shutdown).await {
                    break;
                }
                retry = next_backoff(retry, config.retry_max);
                attempt = attempt.saturating_add(1);
                continue;
            }
        };

        let Some(session_id) = allocate_session_id(&next_session_id) else {
            result.rejected_sessions = result.rejected_sessions.saturating_add(1);
            tracing::debug!(
                transport = TRANSPORT_NETCONF_SSH,
                "NETCONF SSH Call Home session rejected because the session id range is exhausted"
            );
            let wait = deterministic_jitter(retry, attempt, endpoint_index);
            if sleep_or_shutdown(wait, &shutdown).await {
                break;
            }
            retry = next_backoff(retry, config.retry_max);
            attempt = attempt.saturating_add(1);
            continue;
        };

        result.connected_sessions = result.connected_sessions.saturating_add(1);
        let worker = tokio::spawn({
            let server = Arc::clone(&server);
            let ssh_config = Arc::clone(&ssh_config);
            let auth_policy = Arc::clone(&auth_policy);
            let session_config = config.ssh.session;
            let session_registry = session_registry.clone();
            async move {
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
            }
        });

        let clean = wait_for_call_home_worker(worker, &shutdown, config.ssh.drain_timeout).await;
        if clean {
            result.completed_sessions = result.completed_sessions.saturating_add(1);
            retry = config.retry_initial;
            attempt = 0;
        } else {
            result.failed_sessions = result.failed_sessions.saturating_add(1);
            retry = next_backoff(retry, config.retry_max);
            attempt = attempt.saturating_add(1);
        }

        if shutdown.is_shutdown_requested() {
            break;
        }
    }

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
    stream: TcpStream,
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

async fn wait_for_call_home_worker(
    mut worker: JoinHandle<Result<(), SshWorkerError>>,
    shutdown: &ShutdownToken,
    drain_timeout: Duration,
) -> bool {
    tokio::select! {
        joined = &mut worker => matches!(joined, Ok(Ok(()))),
        _ = shutdown.shutdown_acknowledged() => {
            if matches!(
                tokio::time::timeout(drain_timeout, &mut worker).await,
                Ok(Ok(Ok(())))
            ) {
                true
            } else {
                worker.abort();
                let _ = worker.await;
                false
            }
        }
    }
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

fn validate_call_home_config<C, B, P, A>(
    server: &ReadOnlyNetconfServer<C, B, P, A>,
    config: &SshCallHomeConfig,
) -> Result<(), SshCallHomeError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
{
    validate_listener_config(server, &config.ssh)?;
    if config.endpoints.is_empty() {
        return Err(SshCallHomeError::MissingEndpoint);
    }
    if config.connect_timeout.is_zero() {
        return Err(SshCallHomeError::InvalidConnectTimeout);
    }
    if config.retry_initial.is_zero() || config.retry_max < config.retry_initial {
        return Err(SshCallHomeError::InvalidRetryBackoff);
    }
    Ok(())
}

async fn sleep_or_shutdown(duration: Duration, shutdown: &ShutdownToken) -> bool {
    tokio::select! {
        _ = shutdown.shutdown_acknowledged() => true,
        _ = tokio::time::sleep(duration) => false,
    }
}

fn next_backoff(current: Duration, max: Duration) -> Duration {
    current.saturating_mul(2).min(max)
}

fn deterministic_jitter(base: Duration, attempt: u64, endpoint_index: usize) -> Duration {
    let base_millis = base.as_millis();
    if base_millis == 0 {
        return base;
    }
    let spread = (base_millis / CALL_HOME_BACKOFF_JITTER_DIVISOR).max(1);
    let salt = attempt
        .wrapping_mul(1_103_515_245)
        .wrapping_add(endpoint_index as u64);
    let jitter = u128::from(salt) % (spread + 1);
    base.saturating_add(Duration::from_millis(jitter.try_into().unwrap_or(u64::MAX)))
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
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::testkit::{
        assert_ssh_listener_debug_redacted, write_truncated_authorized_key,
        write_truncated_host_key, NetconfSshTestKeyFixture,
    };
    use std::path::PathBuf;

    fn ed25519_key() -> PrivateKey {
        PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).expect("SSH key")
    }

    fn write_host_key(dir: &Path, name: &str, key: &PrivateKey) -> PathBuf {
        let path = dir.join(name);
        let encoded = key
            .to_openssh(keys::ssh_key::LineEnding::LF)
            .expect("OpenSSH private key");
        fs::write(&path, encoded.as_bytes()).expect("write host key");
        path
    }

    fn write_authorized_keys(dir: &Path, contents: &str) -> PathBuf {
        let path = dir.join("authorized_keys");
        fs::write(&path, contents).expect("write authorized keys");
        path
    }

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

    #[test]
    fn ssh_key_file_loader_reads_host_and_authorized_keys() {
        let dir = tempfile::tempdir().expect("tempdir");
        let host_key = ed25519_key();
        let user_key = ed25519_key();
        let host_path = write_host_key(dir.path(), "ssh_host_ed25519_key", &host_key);
        let public_text = user_key.public_key().to_openssh().expect("public key");
        let public_blob = public_text
            .split_whitespace()
            .nth(1)
            .expect("public key blob");
        let authorized_path = write_authorized_keys(
            dir.path(),
            &format!("# comment\n\nfrom=\"127.0.0.1\" {public_text} operator\n"),
        );

        let material = load_ssh_listener_key_files([host_path], &authorized_path)
            .expect("loaded key material");
        assert_eq!(material.host_keys.len(), 1);
        assert_eq!(material.authorized_keys.len(), 1);
        assert_eq!(
            material.authorized_keys[0].key_data(),
            user_key.public_key().key_data()
        );

        let config = SshListenerConfig::new(
            TenantId::from_static("tenant-a"),
            material.host_keys.clone(),
            material.authorized_keys.clone(),
        );
        assert_eq!(config.host_keys.len(), 1);
        assert_eq!(config.authorized_keys.len(), 1);

        let debug = format!("{material:?}");
        assert!(debug.contains("1 key(s)"));
        assert!(!debug.contains(public_blob));
        assert!(!debug.contains("OPENSSH"));
    }

    #[test]
    fn ssh_testkit_fixture_writes_loadable_redaction_safe_key_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fixture = NetconfSshTestKeyFixture::generate().expect("test SSH key fixture");
        let files = fixture
            .write_key_files(dir.path())
            .expect("write key files");

        let material =
            load_ssh_listener_key_files([&files.host_key_path], &files.authorized_keys_path)
                .expect("load generated key files");
        assert_eq!(material.host_keys.len(), 1);
        assert_eq!(material.authorized_keys.len(), 1);
        assert_eq!(
            material.authorized_keys[0].key_data(),
            fixture.listener_key_material().authorized_keys[0].key_data()
        );

        let config = fixture.listener_config(TenantId::from_static("tenant-a"));
        assert_eq!(config.host_keys.len(), 1);
        assert_eq!(config.authorized_keys.len(), 1);
        assert_ssh_listener_debug_redacted(&material, &fixture);
        assert_ssh_listener_debug_redacted(&config, &fixture);
        assert_ssh_listener_debug_redacted(&files, &fixture);

        let truncated_host_key_path = dir.path().join("truncated_host_key");
        write_truncated_host_key(&truncated_host_key_path).expect("write truncated host key");
        let error =
            load_ssh_listener_key_files([&truncated_host_key_path], &files.authorized_keys_path)
                .expect_err("truncated host key");
        assert_eq!(error, SshKeyFileLoadError::HostKeyInvalid { index: 0 });
        assert_eq!(error.as_str(), "netconf_ssh_host_key_invalid");
        assert_eq!(error.to_string(), error.as_str());
        assert!(!format!("{error:?}").contains("OPENSSH"));
        assert!(!format!("{error}").contains("OPENSSH"));

        let truncated_authorized_path = dir.path().join("truncated_authorized_keys");
        write_truncated_authorized_key(&truncated_authorized_path, &fixture)
            .expect("write truncated authorized key");
        let error = load_ssh_listener_key_files([&files.host_key_path], &truncated_authorized_path)
            .expect_err("truncated authorized key");
        assert_eq!(error, SshKeyFileLoadError::AuthorizedKeyInvalid { line: 1 });
        assert_eq!(error.as_str(), "netconf_ssh_authorized_key_invalid");
        assert_eq!(error.to_string(), error.as_str());
        assert!(!format!("{error:?}").contains("OPENSSH"));
        assert!(!format!("{error}").contains("OPENSSH"));
    }

    #[test]
    fn ssh_key_file_loader_rejects_empty_and_comments_only_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let user_key = ed25519_key();
        let public_text = user_key.public_key().to_openssh().expect("public key");
        let authorized_path = write_authorized_keys(dir.path(), &public_text);

        let missing_host =
            load_ssh_listener_key_files(std::iter::empty::<&Path>(), &authorized_path)
                .expect_err("missing host path");
        assert_eq!(missing_host, SshKeyFileLoadError::HostKeyPathMissing);
        assert_eq!(missing_host.as_str(), "netconf_ssh_host_key_path_missing");
        assert_eq!(missing_host.to_string(), missing_host.as_str());

        let empty_host = dir.path().join("empty_host_key");
        fs::write(&empty_host, "\n").expect("write empty host key");
        let error =
            load_ssh_listener_key_files([&empty_host], &authorized_path).expect_err("empty host");
        assert_eq!(error, SshKeyFileLoadError::HostKeyEmpty { index: 0 });
        assert_eq!(error.as_str(), "netconf_ssh_host_key_empty");
        assert_eq!(error.to_string(), error.as_str());

        let host_key = ed25519_key();
        let host_path = write_host_key(dir.path(), "host_key", &host_key);
        let comments_only = write_authorized_keys(dir.path(), "# operator key\n\n  # disabled\n");
        let error = load_ssh_listener_key_files([host_path], comments_only)
            .expect_err("comments only authorized keys");
        assert_eq!(error, SshKeyFileLoadError::AuthorizedKeysNoRecords);
        assert_eq!(error.as_str(), "netconf_ssh_authorized_keys_no_records");
        assert_eq!(error.to_string(), error.as_str());
    }

    #[test]
    fn ssh_key_file_loader_rejects_invalid_and_duplicate_authorized_keys() {
        let dir = tempfile::tempdir().expect("tempdir");
        let host_key = ed25519_key();
        let host_path = write_host_key(dir.path(), "host_key", &host_key);

        let invalid_authorized =
            write_authorized_keys(dir.path(), "# comment\nssh-ed25519 not-base64\n");
        let error = load_ssh_listener_key_files([&host_path], invalid_authorized)
            .expect_err("invalid authorized key");
        assert_eq!(error, SshKeyFileLoadError::AuthorizedKeyInvalid { line: 2 });
        assert_eq!(error.as_str(), "netconf_ssh_authorized_key_invalid");
        assert_eq!(error.to_string(), error.as_str());
        assert!(!format!("{error:?}").contains("not-base64"));

        let user_key = ed25519_key();
        let public_text = user_key.public_key().to_openssh().expect("public key");
        let duplicate_authorized =
            write_authorized_keys(dir.path(), &format!("{public_text}\n{public_text}\n"));
        let error = load_ssh_listener_key_files([host_path], duplicate_authorized)
            .expect_err("duplicate authorized key");
        assert_eq!(
            error,
            SshKeyFileLoadError::AuthorizedKeyDuplicate { line: 2 }
        );
        assert_eq!(error.as_str(), "netconf_ssh_authorized_key_duplicate");
        assert_eq!(error.to_string(), error.as_str());
    }
}
