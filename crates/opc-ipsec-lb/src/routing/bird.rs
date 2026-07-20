//! BIRD routing-daemon adapter over the BIRD control socket.
//!
//! The BIRD remote-control protocol is a stable, documented line protocol on
//! a UNIX domain socket ("you do not necessarily need to use `birdc` to talk
//! to BIRD, your own applications could do that, too" — BIRD User's Guide,
//! Remote control). This adapter speaks it directly with no new dependencies
//! and never shells out to `birdc`.
//!
//! Advertisement intent is realized as one generated `protocol static`
//! fragment per routing domain (host routes only), written atomically and
//! applied with `configure soft`; the operator's main configuration includes
//! the fragment directory and owns all BGP peer, ASN, policy, and BFD setup.
//! The fragment is always rendered from the exact desired set, so the adapter
//! can never originate anything outside it. Per-peer session state is relayed
//! from `show protocols all`, exact local Adj-RIB-Out membership from
//! `show route exported <peer> protocol <static>`, and BFD path health from
//! `show bfd sessions`, correlated by neighbor address. Export readback does
//! not claim that a remote peer installed the route. The adapter never touches
//! BGP or BFD wire protocols itself.
//!
//! Production construction is available only through
//! [`BirdControlSocketAdapter::spawn_supervised`]. The SDK starts BIRD in
//! forced foreground mode through its parent-death helper, keeps the exact
//! spawning thread alive, and admits mutations only while that child remains
//! live. An already-running external BIRD or caller-authored lifecycle claim
//! is deliberately not accepted.
//!
//! Wire-format notes (validated against BIRD 2 replies):
//!
//! - every reply line carries a four-digit code and a separator: `-` for
//!   continuation, space for the final line;
//! - repeated codes on consecutive continuation lines are collapsed to four
//!   spaces plus the separator;
//! - the final success reply of a `show` command is `0000 ` (the trailing
//!   space is significant — naive whitespace trimming destroys it);
//! - `configure` ends in `0003 Reconfigured` on success; `0004`, `0005`, and
//!   `0006` mean the reconfiguration is queued, in progress, or ignored, so
//!   the outcome is ambiguous; `8xxx`/`9xxx` are explicit refusals.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rand::{rngs::SysRng, TryRng};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::error::IpsecLbError;
use crate::model::IpAddress;
use crate::ownership::RoutingDomainTag;
use crate::routing::bird_supervisor::RoutingLifecycleAdmission;
use crate::routing::{
    AdvertisementSetApplyResult, BirdProcessConfig, HostPrefix, PathHealth, PeerIdentity,
    PeerObservation, PeerSessionState, PrefixApplyOutcome, PrefixRejectReason,
    RoutingProcessSupervision, RoutingStackAdapter, RoutingStackKind, RoutingStackProbe,
    MAX_ADVERTISEMENT_ROUTING_DOMAINS, MAX_ROUTING_PEERS_TOTAL,
};

const MAX_PROTOCOL_NAME_LEN: usize = 64;
const BIRD_REPLY_LINE_MAX: usize = 4096;
const BIRD_REPLY_LINES_MAX: usize = 8_192;
const BIRD_REPLY_BYTES_MAX: usize = 1_048_576;
const BIRD_FRAGMENT_BYTES_MAX: u64 = 262_144;
const BIRD_FRAGMENT_DIRECTORY_ENTRIES_MAX: usize = 4_096;
const BIRD_OWNED_FRAGMENT_FILES_MAX: usize = MAX_ADVERTISEMENT_ROUTING_DOMAINS * 2;
const BIRD_FRAGMENT_FILE_PREFIX: &str = "opc-ipsec-lb-domain-";
const BIRD_FRAGMENT_FILE_SUFFIX: &str = ".conf";
const BIRD_FRAGMENT_TEMP_SUFFIX: &str = ".tmp";
const BIRD_FRAGMENT_RANDOM_TEMP_MARKER: &str = ".conf.tmp.";
const BIRD_FRAGMENT_LOCK_FILE: &str = ".opc-ipsec-lb-fragment.lock";
const BIRD_FRAGMENT_MAGIC: &str = "# opc-ipsec-lb-routing-fragment-v1";
const BIRD_COMMAND_TIMEOUT_MAX: Duration = Duration::from_secs(15);
/// A control poll performs one exact export readback per configured peer.
/// Keep one BIRD process's fan-out small enough to execute every readback in
/// one bounded concurrent wave.
const MAX_BIRD_PEERS_PER_DOMAIN: usize = 32;
const MAX_BIRD_PEERS_TOTAL: usize = 32;
/// BIRD reply code: reading configuration (progress, never final).
const REPLY_READING_CONFIG: u16 = 2;
/// BIRD reply code: reconfigured (the only unambiguous configure success).
const REPLY_RECONFIGURED: u16 = 3;

/// Binding between one opaque routing-domain tag and operator-owned BIRD
/// protocol instances.
///
/// `static_protocol` names the generated `protocol static` instance that
/// carries this domain's host routes; `peer_protocols` names the
/// operator-configured BGP instances whose sessions the adapter relays. BFD
/// path health is correlated to peers by neighbor address from
/// `show bfd sessions`. The adapter never creates, selects, or configures
/// peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BirdDomainBinding {
    /// Opaque routing-domain tag.
    pub domain: RoutingDomainTag,
    /// BIRD symbol of the generated static protocol for this domain.
    pub static_protocol: String,
    /// BIRD symbols of the operator-owned BGP peer protocols to observe.
    pub peer_protocols: Vec<String>,
}

/// BIRD control-socket adapter configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BirdAdapterConfig {
    /// Path of the BIRD control socket (`-s` option of `bird`).
    pub socket_path: PathBuf,
    /// Directory of adapter-managed fragments, included by the operator's
    /// main `bird.conf`.
    pub fragment_dir: PathBuf,
    /// Routing-domain bindings.
    pub domains: Vec<BirdDomainBinding>,
    /// Timeout for one control-socket command round-trip.
    pub command_timeout: Duration,
}

impl BirdAdapterConfig {
    /// Validate the adapter configuration.
    pub fn validate(&self) -> Result<(), IpsecLbError> {
        if self.socket_path.as_os_str().is_empty() {
            return Err(IpsecLbError::invalid_config(
                "socket_path",
                "BIRD control socket path must be non-empty",
            ));
        }
        if self.fragment_dir.as_os_str().is_empty() {
            return Err(IpsecLbError::invalid_config(
                "fragment_dir",
                "BIRD fragment directory must be non-empty",
            ));
        }
        if !self.fragment_dir.is_absolute() {
            return Err(IpsecLbError::invalid_config(
                "fragment_dir",
                "BIRD fragment directory must be absolute",
            ));
        }
        if self.domains.is_empty() {
            return Err(IpsecLbError::invalid_config(
                "domains",
                "at least one routing-domain binding is required",
            ));
        }
        if self.domains.len() > MAX_ADVERTISEMENT_ROUTING_DOMAINS {
            return Err(IpsecLbError::invalid_config(
                "domains",
                "routing-domain count exceeds the production bound",
            ));
        }
        if self.command_timeout.is_zero() {
            return Err(IpsecLbError::invalid_config(
                "command_timeout",
                "command timeout must be non-zero",
            ));
        }
        if self.command_timeout > BIRD_COMMAND_TIMEOUT_MAX {
            return Err(IpsecLbError::invalid_config(
                "command_timeout",
                "BIRD command timeout exceeds the production bound",
            ));
        }
        let mut domains = BTreeSet::new();
        let mut protocols = BTreeSet::new();
        let mut peer_count = 0usize;
        for binding in &self.domains {
            if !domains.insert(binding.domain) {
                return Err(IpsecLbError::invalid_config(
                    "domains",
                    "duplicate routing-domain binding",
                ));
            }
            if binding.peer_protocols.len() > MAX_BIRD_PEERS_PER_DOMAIN {
                return Err(IpsecLbError::invalid_config(
                    "peer_protocols",
                    "peer count per routing domain exceeds the production bound",
                ));
            }
            peer_count = peer_count
                .checked_add(binding.peer_protocols.len())
                .ok_or_else(|| {
                    IpsecLbError::invalid_config(
                        "peer_protocols",
                        "total peer count exceeds the production bound",
                    )
                })?;
            if peer_count > MAX_BIRD_PEERS_TOTAL {
                return Err(IpsecLbError::invalid_config(
                    "peer_protocols",
                    "total peer count exceeds the production bound",
                ));
            }
            validate_symbol("static_protocol", &binding.static_protocol)?;
            if !protocols.insert(binding.static_protocol.clone()) {
                return Err(IpsecLbError::invalid_config(
                    "static_protocol",
                    "duplicate BIRD protocol instance name",
                ));
            }
            for peer in &binding.peer_protocols {
                validate_symbol("peer_protocols", peer)?;
                if !protocols.insert(peer.clone()) {
                    return Err(IpsecLbError::invalid_config(
                        "peer_protocols",
                        "duplicate BIRD protocol instance name",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn validate_symbol(field: &'static str, name: &str) -> Result<(), IpsecLbError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_PROTOCOL_NAME_LEN
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if valid {
        Ok(())
    } else {
        Err(IpsecLbError::invalid_config(
            field,
            "BIRD protocol instance names must be non-empty ASCII alphanumeric or underscore",
        ))
    }
}

/// Content and final reply code of one control command.
#[derive(Debug)]
struct BirdReply {
    code: u16,
    lines: Vec<String>,
}

/// How a command round-trip failed.
#[derive(Debug)]
enum BirdCommandError {
    /// Transport, timeout, EOF, or malformed greeting: the stack may or may
    /// not have applied the request. Maps to per-prefix
    /// [`PrefixApplyOutcome::Unreachable`], never to a rejection.
    Io(IpsecLbError),
    /// The stack explicitly refused the command (8xxx/9xxx final reply).
    /// Maps to [`PrefixRejectReason::ConfigureFailed`].
    Refused(u16),
}

impl BirdCommandError {
    fn io(operation: &'static str, error: io::Error) -> Self {
        Self::Io(IpsecLbError::io(operation, error))
    }
}

fn bird_observation_error(error: BirdCommandError) -> IpsecLbError {
    match error {
        BirdCommandError::Io(error) => error,
        BirdCommandError::Refused(_code) => IpsecLbError::io(
            "bird_route_readback",
            io::Error::other("BIRD refused exact route readback"),
        ),
    }
}

/// Adapter toward a BIRD routing daemon over its control socket.
#[derive(Clone)]
pub struct BirdControlSocketAdapter {
    config: BirdAdapterConfig,
    lifecycle: Arc<RoutingLifecycleAdmission>,
    /// Last successfully read BFD health per neighbor. `show bfd sessions`
    /// failures briefly degrade to the cache instead of flapping every peer;
    /// stale cache entries age to `Unknown` after a bounded interval.
    bfd_health_cache: Arc<std::sync::Mutex<BfdHealthCache>>,
    /// Adapter-local serialization remains held by detached workers after an
    /// observer timeout, through late file I/O and mandatory rollback.
    mutation_lock: Arc<tokio::sync::Mutex<()>>,
    fragment_namespace: Arc<FragmentNamespace>,
}

impl fmt::Debug for BirdControlSocketAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BirdControlSocketAdapter")
            .field("domains", &self.config.domains.len())
            .field("process_supervision_ready", &self.lifecycle.is_live())
            .field("bfd_health_cache", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl BirdControlSocketAdapter {
    /// Start and own a foreground BIRD process, then build an admitted adapter.
    ///
    /// This is the only production constructor. It fails closed unless the
    /// SDK helper installs and acknowledges the Linux parent-death boundary,
    /// the dedicated spawning thread remains live, the configured control
    /// socket namespace is private and has no active listener (an owned,
    /// proven-dead stale socket may be reclaimed), and the newly owned BIRD
    /// process answers a status probe before the bounded startup deadline.
    /// The complete canonical adapter-owned fragment namespace is validated
    /// and durably cleared before the child can start.
    pub async fn spawn_supervised(
        mut config: BirdAdapterConfig,
        process: BirdProcessConfig,
    ) -> Result<Self, IpsecLbError> {
        config.validate()?;
        let startup_timeout = process.startup_timeout;
        if startup_timeout.is_zero() {
            return Err(IpsecLbError::invalid_config(
                "startup_timeout",
                "BIRD process startup timeout must be non-zero",
            ));
        }
        let started = Instant::now();
        let fragment_dir = config.fragment_dir.clone();
        let control_socket = config.socket_path.clone();
        let (fragment_namespace, mut prepared_process) = run_bounded_startup_blocking(
            startup_timeout,
            "bird_fragment_pre_spawn_cleanup",
            move || {
                let namespace = Arc::new(FragmentNamespace::open(&fragment_dir)?);
                // A fresh BIRD process must never parse durable advertisement
                // intent left by a previous process.
                namespace.clear_owned_before_spawn_sync()?;
                // Admit and retain the exact launch files and socket namespace
                // under this same deadline. No child exists yet.
                let prepared_process = RoutingLifecycleAdmission::prepare(process, control_socket)?;
                Ok((namespace, prepared_process))
            },
        )
        .await?;
        let remaining = startup_timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(IpsecLbError::io(
                "bird_supervisor_startup",
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "pre-spawn cleanup consumed the BIRD startup deadline",
                ),
            ));
        }
        prepared_process.set_startup_timeout(remaining)?;
        let lifecycle = RoutingLifecycleAdmission::start(prepared_process).await?;
        config.socket_path = lifecycle.control_socket_path().to_owned();
        let adapter = Self {
            config,
            lifecycle,
            bfd_health_cache: Arc::new(std::sync::Mutex::new(BfdHealthCache::default())),
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            fragment_namespace,
        };
        let remaining = startup_timeout.saturating_sub(started.elapsed());
        let ready = tokio::time::timeout(remaining, async {
            loop {
                adapter.lifecycle.ensure_live()?;
                if adapter.command("show status").await.is_ok() {
                    // A socket-path race cannot admit an unrelated responder:
                    // keep the spawning thread/child live across another
                    // supervisor poll and require a second status exchange.
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    adapter.lifecycle.ensure_live()?;
                    if adapter.command("show status").await.is_ok() {
                        adapter.lifecycle.ensure_live()?;
                        return Ok::<(), IpsecLbError>(());
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        match ready {
            Ok(Ok(())) => Ok(adapter),
            Ok(Err(error)) => {
                let _ = adapter.lifecycle.shutdown().await;
                Err(error)
            }
            Err(_) => {
                let _ = adapter.lifecycle.shutdown().await;
                Err(IpsecLbError::io(
                    "bird_supervisor_startup",
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "supervised BIRD control readiness timed out",
                    ),
                ))
            }
        }
    }

    #[cfg(test)]
    fn new_for_conformance(config: BirdAdapterConfig) -> Result<Self, IpsecLbError> {
        config.validate()?;
        let fragment_namespace = Arc::new(FragmentNamespace::open(&config.fragment_dir)?);
        Ok(Self {
            config,
            lifecycle: RoutingLifecycleAdmission::conformance(),
            bfd_health_cache: Arc::new(std::sync::Mutex::new(BfdHealthCache::default())),
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            fragment_namespace,
        })
    }

    /// Terminate the SDK-owned BIRD process and invalidate its admission.
    ///
    /// Dropping the final adapter clone also requests termination without
    /// blocking the caller, but explicit shutdown reports timeout or thread
    /// failure instead of discarding that evidence.
    pub async fn shutdown_supervised(&self) -> Result<(), IpsecLbError> {
        self.lifecycle.shutdown().await
    }

    fn binding(&self, domain: RoutingDomainTag) -> Result<&BirdDomainBinding, IpsecLbError> {
        self.config
            .domains
            .iter()
            .find(|binding| binding.domain == domain)
            .ok_or_else(|| {
                IpsecLbError::invalid_config(
                    "routing_domain",
                    "no BIRD binding for the routing domain",
                )
            })
    }

    async fn protocols_absent(
        &self,
        protocol_names: &BTreeSet<String>,
        operation: &'static str,
    ) -> Result<bool, IpsecLbError> {
        let protocols = self
            .command("show protocols all")
            .await
            .map_err(|error| match error {
                BirdCommandError::Io(error) => error,
                BirdCommandError::Refused(_code) => IpsecLbError::io(
                    operation,
                    io::Error::other("BIRD refused protocol-absence readback"),
                ),
            })?;
        Ok(!protocols.lines.iter().any(|line| {
            line.split_whitespace()
                .next()
                .is_some_and(|name| protocol_names.contains(name))
        }))
    }

    async fn await_protocols_absent(
        &self,
        protocol_names: &BTreeSet<String>,
        operation: &'static str,
    ) -> Result<(), IpsecLbError> {
        tokio::time::timeout(self.config.command_timeout, async {
            loop {
                if self.protocols_absent(protocol_names, operation).await? {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_elapsed| {
            IpsecLbError::io(
                operation,
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "adapter-owned BIRD protocol remained past the readback deadline",
                ),
            )
        })?
    }

    async fn establish_known_absence_inner(&self) -> Result<(), IpsecLbError> {
        let inventory = self.fragment_namespace.inventory().await?;
        let configured_domains: BTreeSet<RoutingDomainTag> = self
            .config
            .domains
            .iter()
            .map(|binding| binding.domain)
            .collect();
        let all_domains: BTreeSet<RoutingDomainTag> = configured_domains
            .iter()
            .copied()
            .chain(inventory.fragments.iter().map(|fragment| fragment.domain))
            .collect();
        if all_domains.len() > MAX_ADVERTISEMENT_ROUTING_DOMAINS {
            return Err(IpsecLbError::invalid_config(
                "fragment_dir",
                "configured and durable routing-domain union exceeds the production bound",
            ));
        }

        let mut protocol_names: BTreeSet<String> = self
            .config
            .domains
            .iter()
            .map(|binding| binding.static_protocol.clone())
            .collect();
        protocol_names.extend(
            inventory
                .fragments
                .iter()
                .map(|fragment| fragment.static_protocol.clone()),
        );

        let mut removal_names: BTreeSet<String> = self
            .config
            .domains
            .iter()
            .map(|binding| fragment_file_name(binding.domain))
            .collect();
        removal_names.extend(
            self.config
                .domains
                .iter()
                .map(|binding| legacy_fragment_temp_name(binding.domain)),
        );
        removal_names.extend(
            inventory
                .fragments
                .into_iter()
                .map(|fragment| fragment.file_name),
        );
        removal_names.extend(inventory.temporary_files);
        for name in removal_names {
            self.fragment_namespace.remove(name).await?;
        }

        match self.command("configure soft").await {
            Ok(reply) if reply.code == REPLY_RECONFIGURED => {}
            Ok(_reply) => {
                return Err(IpsecLbError::io(
                    "bird_startup_configure",
                    io::Error::other("BIRD reconfiguration is queued or in progress"),
                ));
            }
            Err(BirdCommandError::Io(error)) => return Err(error),
            Err(BirdCommandError::Refused(_code)) => {
                return Err(IpsecLbError::io(
                    "bird_startup_configure",
                    io::Error::other("BIRD refused startup known-absence configuration"),
                ));
            }
        }

        if self
            .protocols_absent(&protocol_names, "bird_startup_readback")
            .await?
        {
            Ok(())
        } else {
            Err(IpsecLbError::io(
                "bird_startup_readback",
                io::Error::other("adapter-owned BIRD protocol remains after startup cleanup"),
            ))
        }
    }

    /// Run one control-socket command and return its content lines (reply
    /// codes stripped, code-collapsed continuations reattached) plus the
    /// final reply code.
    async fn command(&self, command: &str) -> Result<BirdReply, BirdCommandError> {
        self.lifecycle.ensure_live().map_err(BirdCommandError::Io)?;
        let operation = || async {
            let stream = UnixStream::connect(&self.config.socket_path)
                .await
                .map_err(|error| BirdCommandError::io("bird_connect", error))?;
            let mut reader = BufReader::new(stream);

            let greeting = read_reply_line(&mut reader).await?;
            if !greeting.starts_with("0001") {
                return Err(BirdCommandError::io(
                    "bird_greeting",
                    io::Error::new(io::ErrorKind::InvalidData, "unexpected BIRD greeting"),
                ));
            }

            let mut request = command.as_bytes().to_vec();
            request.push(b'\n');
            reader
                .get_mut()
                .write_all(&request)
                .await
                .map_err(|error| BirdCommandError::io("bird_command_write", error))?;

            let mut lines = Vec::new();
            let mut reply_bytes = 0usize;
            let mut last_code = 0u16;
            loop {
                let line = read_reply_line(&mut reader).await?;
                match classify_reply_line(&line, &mut last_code) {
                    ReplyLine::Content(text) => {
                        reply_bytes = reply_bytes.checked_add(text.len()).ok_or_else(|| {
                            BirdCommandError::io(
                                "bird_command_read",
                                io::Error::new(io::ErrorKind::InvalidData, "BIRD reply too large"),
                            )
                        })?;
                        if lines.len() >= BIRD_REPLY_LINES_MAX || reply_bytes > BIRD_REPLY_BYTES_MAX
                        {
                            return Err(BirdCommandError::io(
                                "bird_command_read",
                                io::Error::new(io::ErrorKind::InvalidData, "BIRD reply too large"),
                            ));
                        }
                        lines.push(text);
                    }
                    ReplyLine::Progress => {}
                    ReplyLine::Final(code, text) => {
                        if code >= 8000 {
                            return Err(BirdCommandError::Refused(code));
                        }
                        if !text.is_empty() {
                            reply_bytes = reply_bytes.checked_add(text.len()).ok_or_else(|| {
                                BirdCommandError::io(
                                    "bird_command_read",
                                    io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "BIRD reply too large",
                                    ),
                                )
                            })?;
                            if lines.len() >= BIRD_REPLY_LINES_MAX
                                || reply_bytes > BIRD_REPLY_BYTES_MAX
                            {
                                return Err(BirdCommandError::io(
                                    "bird_command_read",
                                    io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "BIRD reply too large",
                                    ),
                                ));
                            }
                            lines.push(text);
                        }
                        return Ok(BirdReply { code, lines });
                    }
                }
            }
        };
        let reply = tokio::time::timeout(self.config.command_timeout, operation())
            .await
            .map_err(|_| {
                BirdCommandError::io(
                    "bird_command",
                    io::Error::new(io::ErrorKind::TimedOut, "BIRD command timed out"),
                )
            })??;
        self.lifecycle.ensure_live().map_err(BirdCommandError::Io)?;
        Ok(reply)
    }

    /// Write or remove this domain's fragment and ask BIRD to reconfigure.
    ///
    /// Local fragment I/O errors surface as errors because BIRD was never
    /// asked to change anything; command-level failures classify as
    /// ambiguous (transport) or refused (explicit 8xxx/9xxx reply).
    async fn apply_fragment(
        &self,
        binding: &BirdDomainBinding,
        desired: &BTreeSet<HostPrefix>,
    ) -> Result<FragmentApply, IpsecLbError> {
        let replacements = BTreeMap::from([(binding.domain, desired.clone())]);
        self.replace_fragments(&replacements, true).await
    }

    /// Apply several fragment replacements around one BIRD configure command.
    #[cfg(test)]
    async fn apply_fragments(
        &self,
        replacements: &BTreeMap<RoutingDomainTag, BTreeSet<HostPrefix>>,
    ) -> Result<FragmentApply, IpsecLbError> {
        self.replace_fragments(replacements, true).await
    }

    /// Replace several fragments around one BIRD configure command.
    ///
    /// Advertisement applies restore previous durable intent unless BIRD
    /// authoritatively accepts the replacement. Withdrawals set
    /// `restore_on_unconfirmed` to false: a failure may require process
    /// fail-stop, but must never durably reintroduce withdrawn intent.
    async fn replace_fragments(
        &self,
        replacements: &BTreeMap<RoutingDomainTag, BTreeSet<HostPrefix>>,
        restore_on_unconfirmed: bool,
    ) -> Result<FragmentApply, IpsecLbError> {
        // Resolve and validate every replacement before the first mutation.
        // A read or render failure can therefore never leave an earlier
        // domain changed without rollback.
        let mut planned = Vec::with_capacity(replacements.len());
        for (domain, desired) in replacements {
            let binding = self.binding(*domain)?;
            let name = fragment_file_name(binding.domain);
            let previous = self.fragment_namespace.read(name.clone()).await?;
            let replacement = if desired.is_empty() {
                None
            } else {
                let fragment = render_fragment(binding, desired);
                if u64::try_from(fragment.len())
                    .map_or(true, |length| length > BIRD_FRAGMENT_BYTES_MAX)
                {
                    return Err(IpsecLbError::invalid_config(
                        "desired_prefixes",
                        "rendered BIRD fragment exceeds the production bound",
                    ));
                }
                Some(fragment.into_bytes())
            };
            planned.push((name, previous, replacement));
        }

        let mut backups: Vec<(String, Option<Vec<u8>>)> = Vec::with_capacity(planned.len());
        for (name, previous, replacement) in planned {
            let change = if let Some(contents) = replacement {
                self.fragment_namespace
                    .write_atomic(name.clone(), contents)
                    .await
            } else {
                self.fragment_namespace.remove(name.clone()).await
            };
            if let Err(error) = change {
                if restore_on_unconfirmed {
                    for (changed_name, changed_previous) in backups.into_iter().rev() {
                        let _ = restore_fragment(
                            &self.fragment_namespace,
                            changed_name,
                            changed_previous,
                        )
                        .await;
                    }
                }
                return Err(error);
            }
            backups.push((name, previous));
        }
        let result = match self.command("configure soft").await {
            Ok(reply) => FragmentApply::Replied(reply.code),
            Err(BirdCommandError::Io(_error)) => FragmentApply::Ambiguous,
            Err(BirdCommandError::Refused(code)) => FragmentApply::Refused(code),
        };
        if restore_on_unconfirmed && !matches!(result, FragmentApply::Replied(REPLY_RECONFIGURED)) {
            // Do not leave refused or indeterminate desired routes in the
            // durable fragment. A later unrelated configure must not make a
            // route that was reported rejected begin originating.
            let mut first_error = None;
            for (name, previous) in backups.into_iter().rev() {
                if let Err(error) = restore_fragment(&self.fragment_namespace, name, previous).await
                {
                    first_error.get_or_insert(error);
                }
            }
            if let Some(error) = first_error {
                return Err(error);
            }
        }
        Ok(result)
    }

    async fn run_mutation<T, F, Fut>(
        &self,
        operation: &'static str,
        mutation: F,
    ) -> Result<T, IpsecLbError>
    where
        T: Send + 'static,
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, IpsecLbError>> + Send + 'static,
    {
        self.lifecycle.ensure_live()?;
        let worker = self.clone();
        let serialization = Arc::clone(&worker.mutation_lock);
        let duration = self.maximum_mutation_duration();
        let driver = tokio::spawn(async move {
            let _serialization = serialization.lock().await;
            worker.lifecycle.ensure_live()?;
            mutation(worker).await
        });
        match tokio::time::timeout(duration, driver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_join_error)) => Err(IpsecLbError::io(
                operation,
                io::Error::other("BIRD mutation worker failed"),
            )),
            Err(_elapsed) => {
                // A late filesystem worker cannot be cancelled safely. Kill
                // the owned BIRD boundary before returning so no detached
                // worker can later configure/revive routes. Durable leftovers
                // are reconciled to known absence before the next spawn.
                self.lifecycle.request_fail_stop();
                Err(IpsecLbError::io(
                    operation,
                    io::Error::new(io::ErrorKind::TimedOut, "BIRD mutation timed out"),
                ))
            }
        }
    }
}

async fn run_bounded_startup_blocking<T, F>(
    timeout: Duration,
    operation: &'static str,
    work: F,
) -> Result<T, IpsecLbError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, IpsecLbError> + Send + 'static,
{
    let driver = tokio::task::spawn_blocking(work);
    match tokio::time::timeout(timeout, driver).await {
        Ok(Ok(result)) => result,
        Ok(Err(_join_error)) => Err(IpsecLbError::io(
            operation,
            io::Error::other("bounded startup worker failed"),
        )),
        Err(_elapsed) => Err(IpsecLbError::io(
            operation,
            io::Error::new(
                io::ErrorKind::TimedOut,
                "bounded startup operation timed out",
            ),
        )),
    }
}

#[derive(Debug, Default)]
struct BfdHealthCache {
    health: BTreeMap<IpAddress, PathHealth>,
    refreshed_at: Option<Instant>,
}

impl BfdHealthCache {
    fn replace(
        &mut self,
        health: BTreeMap<IpAddress, PathHealth>,
        now: Instant,
    ) -> Result<BTreeMap<IpAddress, PathHealth>, IpsecLbError> {
        if health.len() > MAX_ROUTING_PEERS_TOTAL {
            return Err(IpsecLbError::invalid_config(
                "bfd_observations",
                "BFD observation count exceeds the production bound",
            ));
        }
        self.health = health;
        self.refreshed_at = Some(now);
        Ok(self.health.clone())
    }

    fn usable_or_expire(
        &mut self,
        now: Instant,
        maximum_age: Duration,
    ) -> BTreeMap<IpAddress, PathHealth> {
        if self
            .refreshed_at
            .is_some_and(|refreshed| now.saturating_duration_since(refreshed) <= maximum_age)
        {
            return self.health.clone();
        }
        self.health.clear();
        self.refreshed_at = None;
        BTreeMap::new()
    }
}

fn fragment_file_name(domain: RoutingDomainTag) -> String {
    format!(
        "{BIRD_FRAGMENT_FILE_PREFIX}{}{BIRD_FRAGMENT_FILE_SUFFIX}",
        domain.get()
    )
}

fn legacy_fragment_temp_name(domain: RoutingDomainTag) -> String {
    format!(
        "{BIRD_FRAGMENT_FILE_PREFIX}{}{BIRD_FRAGMENT_TEMP_SUFFIX}",
        domain.get()
    )
}

/// Private, descriptor-pinned fragment namespace.
///
/// All owned file operations are relative to the admitted directory
/// descriptor. The path is used only once during admission, after lstat and
/// before a descriptor identity recheck, so later path replacement cannot
/// redirect writes or inventory reads.
#[derive(Clone)]
struct FragmentNamespace {
    directory: Arc<OwnedFd>,
    /// Serializes ownership across adapter instances and processes. The lock
    /// remains held until the last clone of this namespace is dropped.
    _ownership_lock: Arc<OwnedFd>,
}

impl fmt::Debug for FragmentNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FragmentNamespace")
            .field("admitted", &true)
            .finish()
    }
}

impl FragmentNamespace {
    fn open(path: &Path) -> Result<Self, IpsecLbError> {
        use rustix::fs::{
            flock, fstat, openat, statat, AtFlags, FileType, FlockOperation, Mode, OFlags, CWD,
        };

        let before = statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| IpsecLbError::io("bird_fragment_directory_lstat", error.into()))?;
        validate_private_directory_stat(&before)?;
        let directory = openat(
            CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| IpsecLbError::io("bird_fragment_directory_open", error.into()))?;
        let after = fstat(&directory)
            .map_err(|error| IpsecLbError::io("bird_fragment_directory_fstat", error.into()))?;
        validate_private_directory_stat(&after)?;
        if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
            return Err(IpsecLbError::invalid_config(
                "fragment_dir",
                "BIRD fragment directory changed during admission",
            ));
        }

        let ownership_lock = openat(
            &directory,
            BIRD_FRAGMENT_LOCK_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|error| IpsecLbError::io("bird_fragment_lock_open", error.into()))?;
        let lock_stat = fstat(&ownership_lock)
            .map_err(|error| IpsecLbError::io("bird_fragment_lock_stat", error.into()))?;
        if !FileType::from_raw_mode(lock_stat.st_mode).is_file()
            || lock_stat.st_uid != rustix::process::geteuid().as_raw()
            || lock_stat.st_mode & 0o077 != 0
        {
            return Err(IpsecLbError::invalid_config(
                "fragment_dir",
                "BIRD fragment lock must be a private regular file owned by the effective user",
            ));
        }
        flock(&ownership_lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|error| IpsecLbError::io("bird_fragment_lock", io::Error::from(error)))?;
        Ok(Self {
            directory: Arc::new(directory),
            _ownership_lock: Arc::new(ownership_lock),
        })
    }

    async fn inventory(self: &Arc<Self>) -> Result<DurableFragmentInventory, IpsecLbError> {
        let namespace = Arc::clone(self);
        tokio::task::spawn_blocking(move || namespace.inventory_sync())
            .await
            .map_err(|_join_error| {
                IpsecLbError::io(
                    "bird_fragment_inventory",
                    io::Error::other("fragment inventory worker failed"),
                )
            })?
    }

    async fn read(self: &Arc<Self>, name: String) -> Result<Option<Vec<u8>>, IpsecLbError> {
        let namespace = Arc::clone(self);
        tokio::task::spawn_blocking(move || namespace.read_sync(&name))
            .await
            .map_err(|_join_error| {
                IpsecLbError::io(
                    "bird_fragment_read",
                    io::Error::other("fragment read worker failed"),
                )
            })?
    }

    async fn remove(self: &Arc<Self>, name: String) -> Result<(), IpsecLbError> {
        let namespace = Arc::clone(self);
        tokio::task::spawn_blocking(move || namespace.remove_sync(&name))
            .await
            .map_err(|_join_error| {
                IpsecLbError::io(
                    "bird_fragment_remove",
                    io::Error::other("fragment removal worker failed"),
                )
            })?
    }

    async fn write_atomic(
        self: &Arc<Self>,
        name: String,
        contents: Vec<u8>,
    ) -> Result<(), IpsecLbError> {
        let namespace = Arc::clone(self);
        tokio::task::spawn_blocking(move || namespace.write_atomic_sync(&name, &contents))
            .await
            .map_err(|_join_error| {
                IpsecLbError::io(
                    "bird_fragment_write",
                    io::Error::other("fragment write worker failed"),
                )
            })?
    }

    fn inventory_sync(&self) -> Result<DurableFragmentInventory, IpsecLbError> {
        use rustix::fs::Dir;

        let mut directory = Dir::read_from(&*self.directory)
            .map_err(|error| IpsecLbError::io("bird_fragment_inventory", error.into()))?;
        let mut inventory = DurableFragmentInventory::default();
        let mut entry_count = 0usize;
        while let Some(entry) = directory.read() {
            let entry =
                entry.map_err(|error| IpsecLbError::io("bird_fragment_inventory", error.into()))?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            entry_count = entry_count.checked_add(1).ok_or_else(|| {
                IpsecLbError::invalid_config(
                    "fragment_dir",
                    "fragment directory entry count exceeds the production bound",
                )
            })?;
            if entry_count > BIRD_FRAGMENT_DIRECTORY_ENTRIES_MAX {
                return Err(IpsecLbError::invalid_config(
                    "fragment_dir",
                    "fragment directory entry count exceeds the production bound",
                ));
            }
            let file_name = std::str::from_utf8(bytes).map_err(|_| {
                IpsecLbError::invalid_config(
                    "fragment_dir",
                    "fragment directory contains a non-UTF-8 entry",
                )
            })?;
            if !file_name.starts_with(BIRD_FRAGMENT_FILE_PREFIX) {
                continue;
            }
            let owned_count = inventory
                .fragments
                .len()
                .checked_add(inventory.temporary_files.len())
                .and_then(|count| count.checked_add(1))
                .ok_or_else(|| {
                    IpsecLbError::invalid_config(
                        "fragment_dir",
                        "owned fragment count exceeds the production bound",
                    )
                })?;
            if owned_count > BIRD_OWNED_FRAGMENT_FILES_MAX {
                return Err(IpsecLbError::invalid_config(
                    "fragment_dir",
                    "owned fragment count exceeds the production bound",
                ));
            }

            if let Some((base, random)) = file_name.split_once(BIRD_FRAGMENT_RANDOM_TEMP_MARKER) {
                if random.len() != 32 || !random.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(IpsecLbError::invalid_config(
                        "fragment_dir",
                        "malformed owned temporary fragment filename",
                    ));
                }
                let canonical = format!("{base}{BIRD_FRAGMENT_FILE_SUFFIX}");
                parse_fragment_domain(&canonical, BIRD_FRAGMENT_FILE_SUFFIX)?;
                self.validate_regular_owned(file_name, BIRD_FRAGMENT_BYTES_MAX)?;
                inventory.temporary_files.push(file_name.to_owned());
                continue;
            }
            if file_name.ends_with(BIRD_FRAGMENT_TEMP_SUFFIX) {
                parse_fragment_domain(file_name, BIRD_FRAGMENT_TEMP_SUFFIX)?;
                self.validate_regular_owned(file_name, BIRD_FRAGMENT_BYTES_MAX)?;
                inventory.temporary_files.push(file_name.to_owned());
                continue;
            }
            let domain = parse_fragment_domain(file_name, BIRD_FRAGMENT_FILE_SUFFIX)?;
            let contents = self.read_sync(file_name)?.ok_or_else(|| {
                IpsecLbError::io(
                    "bird_fragment_inventory",
                    io::Error::new(io::ErrorKind::NotFound, "owned fragment vanished"),
                )
            })?;
            let contents = String::from_utf8(contents).map_err(|_| {
                IpsecLbError::invalid_config("fragment", "owned BIRD fragment is not UTF-8")
            })?;
            let static_protocol = parse_owned_fragment(&contents, domain)?;
            inventory.fragments.push(DiscoveredFragment {
                file_name: file_name.to_owned(),
                domain,
                static_protocol,
            });
        }
        Ok(inventory)
    }

    fn clear_owned_before_spawn_sync(&self) -> Result<(), IpsecLbError> {
        let inventory = self.inventory_sync()?;
        let mut removal_names: BTreeSet<String> = inventory
            .fragments
            .into_iter()
            .map(|fragment| fragment.file_name)
            .collect();
        removal_names.extend(inventory.temporary_files);
        for name in removal_names {
            self.remove_sync(&name)?;
        }
        Ok(())
    }

    fn read_sync(&self, name: &str) -> Result<Option<Vec<u8>>, IpsecLbError> {
        use rustix::fs::{fstat, openat, Mode, OFlags};

        if !valid_fragment_leaf_name(name) {
            return Err(IpsecLbError::invalid_config(
                "fragment",
                "fragment name is not a safe leaf name",
            ));
        }
        if !self.exists(name)? {
            return Ok(None);
        }
        let descriptor = openat(
            &*self.directory,
            name,
            // A canonical candidate can be replaced with a FIFO between the
            // metadata probe and this descriptor open. NONBLOCK lets fstat
            // reject that special file instead of stranding startup forever.
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| IpsecLbError::io("bird_fragment_read", error.into()))?;
        let metadata = fstat(&descriptor)
            .map_err(|error| IpsecLbError::io("bird_fragment_read", error.into()))?;
        validate_regular_owned_stat(&metadata, BIRD_FRAGMENT_BYTES_MAX)?;
        let mut file = std::fs::File::from(descriptor);
        let mut contents = Vec::new();
        Read::by_ref(&mut file)
            .take(BIRD_FRAGMENT_BYTES_MAX.saturating_add(1))
            .read_to_end(&mut contents)
            .map_err(|error| IpsecLbError::io("bird_fragment_read", error))?;
        if u64::try_from(contents.len()).map_or(true, |length| length > BIRD_FRAGMENT_BYTES_MAX) {
            return Err(IpsecLbError::invalid_config(
                "fragment",
                "existing BIRD fragment exceeds the production bound",
            ));
        }
        Ok(Some(contents))
    }

    fn write_atomic_sync(&self, name: &str, contents: &[u8]) -> Result<(), IpsecLbError> {
        use rustix::fs::{fsync, openat, renameat, unlinkat, AtFlags, Mode, OFlags};

        if !valid_fragment_leaf_name(name) {
            return Err(IpsecLbError::invalid_config(
                "fragment",
                "fragment name is not a safe leaf name",
            ));
        }
        if u64::try_from(contents.len()).map_or(true, |length| length > BIRD_FRAGMENT_BYTES_MAX) {
            return Err(IpsecLbError::invalid_config(
                "fragment",
                "rendered BIRD fragment exceeds the production bound",
            ));
        }
        if self.exists(name)? {
            self.validate_regular_owned(name, BIRD_FRAGMENT_BYTES_MAX)?;
        }

        let mut temporary = None;
        let mut descriptor = None;
        for _ in 0..8 {
            let high = SysRng
                .try_next_u64()
                .map_err(|_| IpsecLbError::EntropyUnavailable)?;
            let low = SysRng
                .try_next_u64()
                .map_err(|_| IpsecLbError::EntropyUnavailable)?;
            let candidate = format!("{name}.tmp.{high:016x}{low:016x}");
            match openat(
                &*self.directory,
                &candidate,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            ) {
                Ok(file) => {
                    temporary = Some(candidate);
                    descriptor = Some(file);
                    break;
                }
                Err(rustix::io::Errno::EXIST) => {}
                Err(error) => {
                    return Err(IpsecLbError::io("bird_fragment_write", error.into()));
                }
            }
        }
        let temporary = temporary.ok_or_else(|| {
            IpsecLbError::io(
                "bird_fragment_write",
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "could not allocate an exclusive fragment temporary file",
                ),
            )
        })?;
        let descriptor = descriptor.ok_or_else(|| {
            IpsecLbError::io(
                "bird_fragment_write",
                io::Error::other("exclusive fragment descriptor is missing"),
            )
        })?;
        let result = (|| {
            let mut file = std::fs::File::from(descriptor);
            file.write_all(contents)?;
            file.sync_all()?;
            drop(file);
            renameat(&*self.directory, &temporary, &*self.directory, name)
                .map_err(io::Error::from)?;
            fsync(&*self.directory).map_err(io::Error::from)?;
            Ok::<(), io::Error>(())
        })();
        if let Err(error) = result {
            let _ = unlinkat(&*self.directory, &temporary, AtFlags::empty());
            return Err(IpsecLbError::io("bird_fragment_write", error));
        }
        Ok(())
    }

    fn remove_sync(&self, name: &str) -> Result<(), IpsecLbError> {
        use rustix::fs::{fsync, unlinkat, AtFlags};

        if !valid_fragment_leaf_name(name) {
            return Err(IpsecLbError::invalid_config(
                "fragment",
                "fragment name is not a safe leaf name",
            ));
        }
        if !self.exists(name)? {
            return Ok(());
        }
        self.validate_regular_owned(name, BIRD_FRAGMENT_BYTES_MAX)?;
        unlinkat(&*self.directory, name, AtFlags::empty())
            .map_err(|error| IpsecLbError::io("bird_fragment_remove", error.into()))?;
        fsync(&*self.directory)
            .map_err(|error| IpsecLbError::io("bird_fragment_directory_sync", error.into()))?;
        Ok(())
    }

    fn exists(&self, name: &str) -> Result<bool, IpsecLbError> {
        use rustix::fs::{statat, AtFlags};

        match statat(&*self.directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(error) => Err(IpsecLbError::io("bird_fragment_stat", error.into())),
        }
    }

    fn validate_regular_owned(&self, name: &str, max: u64) -> Result<(), IpsecLbError> {
        use rustix::fs::{statat, AtFlags};

        let metadata = statat(&*self.directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| IpsecLbError::io("bird_fragment_stat", error.into()))?;
        validate_regular_owned_stat(&metadata, max)
    }
}

fn valid_fragment_leaf_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\0')
        && name.starts_with(BIRD_FRAGMENT_FILE_PREFIX)
}

fn validate_private_directory_stat(metadata: &rustix::fs::Stat) -> Result<(), IpsecLbError> {
    if !rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_dir()
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o700 != 0o700
        || metadata.st_mode & 0o077 != 0
    {
        return Err(IpsecLbError::invalid_config(
            "fragment_dir",
            "BIRD fragment directory must be mode 0700 and owned by the effective user",
        ));
    }
    Ok(())
}

fn validate_regular_owned_stat(metadata: &rustix::fs::Stat, max: u64) -> Result<(), IpsecLbError> {
    if !rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_file()
        || metadata.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(IpsecLbError::invalid_config(
            "fragment",
            "owned fragment candidate must be a regular file owned by the effective user",
        ));
    }
    if metadata.st_size.is_negative()
        || u64::try_from(metadata.st_size).map_or(true, |size| size > max)
    {
        return Err(IpsecLbError::invalid_config(
            "fragment",
            "existing BIRD fragment exceeds the production bound",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct DiscoveredFragment {
    file_name: String,
    domain: RoutingDomainTag,
    static_protocol: String,
}

#[derive(Debug, Default)]
struct DurableFragmentInventory {
    fragments: Vec<DiscoveredFragment>,
    temporary_files: Vec<String>,
}

fn parse_fragment_domain(
    file_name: &str,
    suffix: &'static str,
) -> Result<RoutingDomainTag, IpsecLbError> {
    let Some(raw_domain) = file_name
        .strip_prefix(BIRD_FRAGMENT_FILE_PREFIX)
        .and_then(|rest| rest.strip_suffix(suffix))
    else {
        return Err(IpsecLbError::invalid_config(
            "fragment_dir",
            "malformed owned fragment filename",
        ));
    };
    if raw_domain.is_empty() || !raw_domain.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(IpsecLbError::invalid_config(
            "fragment_dir",
            "malformed owned fragment filename",
        ));
    }
    raw_domain
        .parse::<u64>()
        .map(RoutingDomainTag::new)
        .map_err(|_| {
            IpsecLbError::invalid_config(
                "fragment_dir",
                "owned fragment routing domain is out of range",
            )
        })
}

fn parse_owned_fragment(
    contents: &str,
    file_domain: RoutingDomainTag,
) -> Result<String, IpsecLbError> {
    let mut lines = contents.lines();
    if lines.next() != Some(BIRD_FRAGMENT_MAGIC) {
        return Err(IpsecLbError::invalid_config(
            "fragment",
            "owned BIRD fragment has an unknown or missing format marker",
        ));
    }
    let expected_domain = format!("# routing-domain: {}", file_domain.get());
    if lines.next() != Some(expected_domain.as_str()) {
        return Err(IpsecLbError::invalid_config(
            "fragment",
            "owned BIRD fragment routing domain does not match its filename",
        ));
    }
    let Some(static_protocol) = lines
        .next()
        .and_then(|line| line.strip_prefix("# static-protocol: "))
    else {
        return Err(IpsecLbError::invalid_config(
            "fragment",
            "owned BIRD fragment is missing protocol identity",
        ));
    };
    validate_symbol("fragment", static_protocol)?;
    let expected_declaration = format!("protocol static {static_protocol} {{");
    if lines.next() != Some(expected_declaration.as_str()) {
        return Err(IpsecLbError::invalid_config(
            "fragment",
            "owned BIRD fragment protocol declaration is malformed",
        ));
    }

    let mut desired = BTreeSet::new();
    let mut family = None;
    let mut saw_v4 = false;
    let mut saw_v6 = false;
    let mut closed = false;
    for line in lines.by_ref() {
        match line {
            "    ipv4;" if !saw_v4 && !saw_v6 => {
                saw_v4 = true;
                family = Some(false);
            }
            "    ipv6;" if !saw_v6 => {
                saw_v6 = true;
                family = Some(true);
            }
            "}" => {
                closed = true;
                break;
            }
            _ => {
                let token = line
                    .strip_prefix("    route ")
                    .and_then(|rest| rest.strip_suffix(" blackhole;"))
                    .ok_or_else(|| {
                        IpsecLbError::invalid_config(
                            "fragment",
                            "owned BIRD fragment contains unsupported syntax",
                        )
                    })?;
                let (address, length) = token.split_once('/').ok_or_else(|| {
                    IpsecLbError::invalid_config(
                        "fragment",
                        "owned BIRD fragment contains a malformed route",
                    )
                })?;
                if length.contains('/') {
                    return Err(IpsecLbError::invalid_config(
                        "fragment",
                        "owned BIRD fragment contains a malformed route",
                    ));
                }
                let address = IpAddr::from_str(address).map_err(|_| {
                    IpsecLbError::invalid_config(
                        "fragment",
                        "owned BIRD fragment contains an invalid route address",
                    )
                })?;
                let prefix = match (address, length, family) {
                    (IpAddr::V4(address), "32", Some(false)) => {
                        HostPrefix::new(IpAddress::V4(address.octets()))
                    }
                    (IpAddr::V6(address), "128", Some(true)) => {
                        HostPrefix::new(IpAddress::V6(address.octets()))
                    }
                    (IpAddr::V4(_), _, _) | (IpAddr::V6(_), _, _) => {
                        return Err(IpsecLbError::invalid_config(
                            "fragment",
                            "owned BIRD fragment route family or prefix length is invalid",
                        ));
                    }
                };
                if !desired.insert(prefix) {
                    return Err(IpsecLbError::invalid_config(
                        "fragment",
                        "owned BIRD fragment contains a duplicate route",
                    ));
                }
                if desired.len() > crate::routing::MAX_ADVERTISED_PREFIXES_PER_DOMAIN {
                    return Err(IpsecLbError::invalid_config(
                        "fragment",
                        "owned BIRD fragment route count exceeds the production bound",
                    ));
                }
            }
        }
    }
    if !closed || lines.next().is_some() {
        return Err(IpsecLbError::invalid_config(
            "fragment",
            "owned BIRD fragment is unterminated or contains trailing content",
        ));
    }
    let binding = BirdDomainBinding {
        domain: file_domain,
        static_protocol: static_protocol.to_owned(),
        peer_protocols: Vec::new(),
    };
    if render_fragment(&binding, &desired) != contents {
        return Err(IpsecLbError::invalid_config(
            "fragment",
            "owned BIRD fragment is not in the canonical generated form",
        ));
    }
    Ok(static_protocol.to_owned())
}

async fn restore_fragment(
    namespace: &Arc<FragmentNamespace>,
    name: String,
    previous: Option<Vec<u8>>,
) -> Result<(), IpsecLbError> {
    match previous {
        Some(contents) => namespace.write_atomic(name, contents).await,
        None => namespace.remove(name).await,
    }
}

/// Outcome of writing the fragment and issuing `configure soft`.
#[derive(Debug)]
enum FragmentApply {
    /// BIRD answered the configure command with this final reply code.
    Replied(u16),
    /// The configure command failed at transport level (disconnect, timeout,
    /// EOF): BIRD may or may not have applied the fragment.
    Ambiguous,
    /// BIRD explicitly refused the reconfiguration (8xxx/9xxx).
    Refused(u16),
}

/// Read one reply line, enforcing the line-length bound during the read.
///
/// Only CR and LF are stripped from the end: the trailing space of the
/// `0000 ` final reply is significant reply framing and must survive.
async fn read_reply_line(reader: &mut BufReader<UnixStream>) -> Result<String, BirdCommandError> {
    let mut line = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|error| BirdCommandError::io("bird_command_read", error))?;
        if available.is_empty() {
            return Err(BirdCommandError::io(
                "bird_command_read",
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "BIRD closed the control socket",
                ),
            ));
        }
        match available.iter().position(|byte| *byte == b'\n') {
            Some(position) => {
                line.extend_from_slice(&available[..position]);
                reader.consume(position + 1);
                if line.len() > BIRD_REPLY_LINE_MAX {
                    return Err(BirdCommandError::io(
                        "bird_command_read",
                        io::Error::new(io::ErrorKind::InvalidData, "BIRD reply line too long"),
                    ));
                }
                while matches!(line.last(), Some(b'\r')) {
                    line.pop();
                }
                return String::from_utf8(line).map_err(|_| {
                    BirdCommandError::io(
                        "bird_command_read",
                        io::Error::new(io::ErrorKind::InvalidData, "BIRD reply is not UTF-8"),
                    )
                });
            }
            None => {
                if line.len() + available.len() > BIRD_REPLY_LINE_MAX {
                    return Err(BirdCommandError::io(
                        "bird_command_read",
                        io::Error::new(io::ErrorKind::InvalidData, "BIRD reply line too long"),
                    ));
                }
                line.extend_from_slice(available);
                let consumed = available.len();
                reader.consume(consumed);
            }
        }
    }
}

/// One classified reply line.
#[derive(Debug, PartialEq, Eq)]
enum ReplyLine {
    /// Content of a multi-line reply.
    Content(String),
    /// Progress report (0002 reading configuration); keep reading.
    Progress,
    /// Final reply carrying its code.
    Final(u16, String),
}

/// Classify one wire line after CR/LF stripping.
///
/// Handles the BIRD framing quirks: repeated continuation codes are
/// collapsed to a single space plus the original text (nest/cli.c), and
/// final replies may carry empty text (`0000 `) or no trailing separator
/// at all (bare `0000`).
fn classify_reply_line(line: &str, last_code: &mut u16) -> ReplyLine {
    let bytes = line.as_bytes();
    if bytes.len() >= 5
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && matches!(bytes[4], b' ' | b'-')
    {
        let code: u16 = line[..4].parse().unwrap_or(0);
        *last_code = code;
        if bytes[4] == b'-' {
            return ReplyLine::Content(line[5..].to_owned());
        }
        if code == REPLY_READING_CONFIG {
            return ReplyLine::Progress;
        }
        return ReplyLine::Final(code, line[5..].to_owned());
    }
    if bytes.first() == Some(&b' ') {
        // Code-collapsed continuation of the previous reply line: exactly
        // one space replaces code and separator; final replies always carry
        // their code explicitly, so this is never a terminator.
        let _ = last_code;
        return ReplyLine::Content(line[1..].to_owned());
    }
    if bytes.len() == 4 && bytes.iter().all(u8::is_ascii_digit) {
        let code: u16 = line.parse().unwrap_or(0);
        *last_code = code;
        return ReplyLine::Final(code, String::new());
    }
    ReplyLine::Content(line.to_owned())
}

/// Render the `protocol static` fragment for the exact desired set.
fn render_fragment(binding: &BirdDomainBinding, desired: &BTreeSet<HostPrefix>) -> String {
    let mut fragment = format!(
        "{BIRD_FRAGMENT_MAGIC}\n# routing-domain: {}\n# static-protocol: {}\n",
        binding.domain.get(),
        binding.static_protocol
    );
    fragment.push_str(&format!("protocol static {} {{\n", binding.static_protocol));
    let v4: Vec<&HostPrefix> = desired
        .iter()
        .filter(|prefix| prefix.address().is_ipv4())
        .collect();
    let v6: Vec<&HostPrefix> = desired
        .iter()
        .filter(|prefix| !prefix.address().is_ipv4())
        .collect();
    if !v4.is_empty() {
        fragment.push_str("    ipv4;\n");
        for prefix in v4 {
            fragment.push_str(&format!(
                "    route {} blackhole;\n",
                render_prefix(*prefix)
            ));
        }
    }
    if !v6.is_empty() {
        fragment.push_str("    ipv6;\n");
        for prefix in v6 {
            fragment.push_str(&format!(
                "    route {} blackhole;\n",
                render_prefix(*prefix)
            ));
        }
    }
    fragment.push_str("}\n");
    fragment
}

fn render_prefix(prefix: HostPrefix) -> String {
    match prefix.address() {
        IpAddress::V4(octets) => format!("{}/32", Ipv4Addr::from(octets)),
        IpAddress::V6(octets) => format!("{}/128", Ipv6Addr::from(octets)),
    }
}

/// One parsed protocol block from `show protocols all`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedProtocol {
    name: String,
    session: PeerSessionState,
    neighbor_address: Option<IpAddress>,
}

/// Known BGP session-state keywords BIRD prints in the `Info` column.
///
/// Scanning for these keywords instead of splitting at a fixed column keeps
/// the parser correct when an operator's `timeformat` puts spaces in the
/// `Since` column. A keyword that is absent (protocol feeding, filters
/// reloaded, or an unrecognized future state) falls back to `Connecting`
/// for an `up` protocol and `Down` otherwise — visible, never silently
/// dropped.
fn parse_session_state(up: bool, tokens: &[&str]) -> PeerSessionState {
    if !up {
        return PeerSessionState::Down;
    }
    for token in tokens {
        match *token {
            "Established" => return PeerSessionState::Established,
            "Idle" | "Connect" | "Active" | "OpenSent" | "OpenConfirm" => {
                return PeerSessionState::Connecting;
            }
            _ => {}
        }
    }
    PeerSessionState::Connecting
}

/// Parse `show protocols all` output into protocol blocks.
///
/// Block headers are unindented rows of the shape
/// `name proto table state since info...`. The protocol-state column accepts
/// `up` and `down` as well as the transient `start`, `stop`, and `flush`
/// states BIRD reports while protocols restart — all non-`up` states are
/// classified as session `Down`, so a restarting peer is relayed as down
/// instead of vanishing from the observation set (which would read as a
/// spurious session close).
fn parse_show_protocols_all(output: &[String]) -> Vec<ParsedProtocol> {
    let mut protocols: Vec<ParsedProtocol> = Vec::new();
    for line in output {
        if line.starts_with(char::is_whitespace) {
            let detail = line.trim();
            if let Some(protocol) = protocols.last_mut() {
                if let Some(address) = detail.strip_prefix("Neighbor address:") {
                    protocol.neighbor_address = parse_bird_neighbor(address.trim());
                }
            }
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() >= 5 && matches!(tokens[3], "up" | "down" | "start" | "stop" | "flush") {
            protocols.push(ParsedProtocol {
                name: tokens[0].to_owned(),
                session: parse_session_state(tokens[3] == "up", &tokens[4..]),
                neighbor_address: None,
            });
        }
    }
    protocols
}

/// Parse `show bfd sessions` output into per-neighbor path health.
///
/// The real BIRD 2 output is a table per BFD instance (reply code 1020):
///
/// ```text
/// bfd1:
/// IP address                Interface  State      Since         Interval  Timeout
/// 192.0.2.1                 eth0       Up         10:00:00.000  0.050     0.250
/// ```
///
/// Lines that do not start with a parseable neighbor address (instance
/// headers, the column header) are skipped. Link-local neighbors are
/// printed with a `%zone` suffix (`fe80::1%eth0`); the zone is dropped for
/// correlation. Multiple sessions to the same neighbor fold
/// conservatively: the worst reported state wins (`Down` beats `AdminDown`
/// beats `Unknown` beats `Up`).
fn parse_show_bfd_sessions(output: &[String]) -> BTreeMap<IpAddress, PathHealth> {
    let mut health: BTreeMap<IpAddress, PathHealth> = BTreeMap::new();
    for line in output {
        let mut tokens = line.split_whitespace();
        let Some(address) = tokens.next().and_then(parse_bird_neighbor) else {
            continue;
        };
        let Some(_interface) = tokens.next() else {
            continue;
        };
        let Some(state) = tokens.next() else {
            continue;
        };
        let state = parse_bfd_state(state);
        health
            .entry(address)
            .and_modify(|current| *current = merge_path_health(*current, state))
            .or_insert(state);
    }
    health
}

/// Conservative fold of several BFD sessions to one neighbor.
fn merge_path_health(a: PathHealth, b: PathHealth) -> PathHealth {
    match (a, b) {
        (PathHealth::Down, _) | (_, PathHealth::Down) => PathHealth::Down,
        (PathHealth::AdminDown, _) | (_, PathHealth::AdminDown) => PathHealth::AdminDown,
        (PathHealth::Unknown, _) | (_, PathHealth::Unknown) => PathHealth::Unknown,
        _ => PathHealth::Up,
    }
}

/// Parse a BIRD neighbor address, dropping any `%zone` suffix BIRD prints
/// for link-local BGP and BFD neighbors so both views correlate.
fn parse_bird_neighbor(text: &str) -> Option<IpAddress> {
    parse_ip_address(text.split('%').next()?)
}

fn parse_ip_address(text: &str) -> Option<IpAddress> {
    match IpAddr::from_str(text).ok()? {
        IpAddr::V4(address) => Some(IpAddress::V4(address.octets())),
        IpAddr::V6(address) => Some(IpAddress::V6(address.octets())),
    }
}

fn parse_bfd_state(text: &str) -> PathHealth {
    match text {
        "Up" => PathHealth::Up,
        "Down" => PathHealth::Down,
        "AdminDown" | "Admin down" => PathHealth::AdminDown,
        _ => PathHealth::Unknown,
    }
}

/// Strictly extract exact host prefixes from one BIRD `show route` reply.
///
/// Headers and attribute continuation lines have no prefix as their first
/// token and are ignored. Any prefix-shaped token must be a canonical host
/// route, unique, bounded, and a member of the adapter-owned local set.
fn parse_show_route_host_prefixes(output: &[String]) -> Result<BTreeSet<HostPrefix>, IpsecLbError> {
    let mut prefixes = BTreeSet::new();
    for line in output {
        let Some(token) = line.split_whitespace().next() else {
            continue;
        };
        if !token.contains('/') {
            continue;
        }
        let (address, length) = token.split_once('/').ok_or_else(|| {
            IpsecLbError::io(
                "bird_route_readback",
                io::Error::new(io::ErrorKind::InvalidData, "malformed BIRD route prefix"),
            )
        })?;
        if length.contains('/') {
            return Err(IpsecLbError::io(
                "bird_route_readback",
                io::Error::new(io::ErrorKind::InvalidData, "malformed BIRD route prefix"),
            ));
        }
        let address = IpAddr::from_str(address).map_err(|_| {
            IpsecLbError::io(
                "bird_route_readback",
                io::Error::new(io::ErrorKind::InvalidData, "invalid BIRD route address"),
            )
        })?;
        let length = length.parse::<u8>().map_err(|_| {
            IpsecLbError::io(
                "bird_route_readback",
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid BIRD route prefix length",
                ),
            )
        })?;
        let prefix = match address {
            IpAddr::V4(address) if length == 32 => HostPrefix::new(IpAddress::V4(address.octets())),
            IpAddr::V6(address) if length == 128 => {
                HostPrefix::new(IpAddress::V6(address.octets()))
            }
            IpAddr::V4(_) | IpAddr::V6(_) => {
                return Err(IpsecLbError::io(
                    "bird_route_readback",
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "BIRD route readback contains a non-host prefix",
                    ),
                ));
            }
        };
        if !prefixes.insert(prefix) {
            return Err(IpsecLbError::adapter_contract_violation(
                "bird_duplicate_route_readback",
            ));
        }
        if prefixes.len() > crate::routing::MAX_ADVERTISED_PREFIXES_PER_DOMAIN {
            return Err(IpsecLbError::adapter_contract_violation(
                "bird_route_readback_bound_exceeded",
            ));
        }
    }
    Ok(prefixes)
}

#[async_trait]
impl RoutingStackAdapter for BirdControlSocketAdapter {
    fn process_supervision(&self) -> &RoutingProcessSupervision {
        self.lifecycle.process_supervision()
    }

    fn managed_domains(&self) -> BTreeSet<RoutingDomainTag> {
        self.config
            .domains
            .iter()
            .map(|binding| binding.domain)
            .collect()
    }

    fn maximum_mutation_duration(&self) -> Duration {
        // Worst apply path: configure, readback, accepted-subset configure,
        // and final readback. File operations are local bounded fragments.
        self.config.command_timeout.saturating_mul(4)
    }

    async fn establish_known_absence(&self) -> Result<(), IpsecLbError> {
        let result = self
            .run_mutation("bird_startup_mutation", |adapter| async move {
                adapter.establish_known_absence_inner().await
            })
            .await;
        if result.is_err() {
            // Startup admission cannot continue when durable absence was not
            // proved. Kill the owned routing boundary before returning so a
            // refused, ambiguous, or failed readback cannot leave stale
            // advertisements live behind a failed service initialization.
            self.lifecycle.request_fail_stop();
        }
        result
    }

    async fn apply_advertisement_set(
        &self,
        domain: RoutingDomainTag,
        desired: &BTreeSet<HostPrefix>,
    ) -> Result<AdvertisementSetApplyResult, IpsecLbError> {
        if desired.len() > crate::routing::MAX_ADVERTISED_PREFIXES_PER_DOMAIN {
            return Err(IpsecLbError::invalid_config(
                "desired_prefixes",
                "desired prefix set exceeds the production bound",
            ));
        }
        let desired = desired.clone();
        self.run_mutation("bird_apply_mutation", move |adapter| async move {
            let binding = adapter.binding(domain)?;
            let rejected = |reason: PrefixRejectReason| {
                desired
                    .iter()
                    .map(|prefix| (*prefix, PrefixApplyOutcome::Rejected(reason)))
                    .collect()
            };
            let unreachable = || {
                desired
                    .iter()
                    .map(|prefix| (*prefix, PrefixApplyOutcome::Unreachable))
                    .collect()
            };

            let configure_code = match adapter.apply_fragment(binding, &desired).await? {
                FragmentApply::Ambiguous => {
                    // Mid-command disconnect, timeout, or EOF in the configure
                    // leg: BIRD may or may not have applied the fragment. This
                    // is ambiguous, never a definitive rejection.
                    return Ok(AdvertisementSetApplyResult::ambiguous(unreachable()));
                }
                FragmentApply::Refused(_code) => {
                    return Ok(AdvertisementSetApplyResult::refused(rejected(
                        PrefixRejectReason::ConfigureFailed,
                    )));
                }
                FragmentApply::Replied(code) => code,
            };
            if configure_code != REPLY_RECONFIGURED {
                // 0004/0005/0006 (queued/in-progress/ignored) and any other
                // non-refusal code: the reconfiguration may still land.
                return Ok(AdvertisementSetApplyResult::ambiguous(unreachable()));
            }
            if desired.is_empty() {
                let names = BTreeSet::from([binding.static_protocol.clone()]);
                return match adapter
                    .await_protocols_absent(&names, "bird_apply_withdraw_readback")
                    .await
                {
                    Ok(()) => Ok(AdvertisementSetApplyResult::applied(BTreeMap::new())),
                    Err(_) => Ok(AdvertisementSetApplyResult::ambiguous(BTreeMap::new())),
                };
            }
            match adapter
                .command(&format!("show route protocol {}", binding.static_protocol))
                .await
            {
                Ok(reply) => {
                    let originated = match parse_show_route_host_prefixes(&reply.lines) {
                        Ok(originated) => originated,
                        Err(_) => {
                            return Ok(AdvertisementSetApplyResult::ambiguous(unreachable()));
                        }
                    };
                    if !originated.is_subset(&desired) {
                        return Ok(AdvertisementSetApplyResult::ambiguous(unreachable()));
                    }
                    let outcomes: BTreeMap<HostPrefix, PrefixApplyOutcome> = desired
                        .iter()
                        .map(|prefix| {
                            let outcome = if originated.contains(prefix) {
                                PrefixApplyOutcome::Accepted
                            } else {
                                PrefixApplyOutcome::Rejected(PrefixRejectReason::StackRejected)
                            };
                            (*prefix, outcome)
                        })
                        .collect();
                    let accepted: BTreeSet<HostPrefix> = outcomes
                        .iter()
                        .filter_map(|(prefix, outcome)| {
                            (*outcome == PrefixApplyOutcome::Accepted).then_some(*prefix)
                        })
                        .collect();
                    if accepted != desired {
                        // Remove readback-rejected routes from the durable static
                        // fragment and prove the accepted subset exactly. Without
                        // this second replacement, a rejected route could begin
                        // originating after a later unrelated configure.
                        if !matches!(
                            adapter.apply_fragment(binding, &accepted).await?,
                            FragmentApply::Replied(REPLY_RECONFIGURED)
                        ) {
                            return Ok(AdvertisementSetApplyResult::ambiguous(unreachable()));
                        }
                        if accepted.is_empty() {
                            return Ok(AdvertisementSetApplyResult::applied(outcomes));
                        }
                        let verified = match adapter
                            .command(&format!("show route protocol {}", binding.static_protocol))
                            .await
                        {
                            Ok(reply) => match parse_show_route_host_prefixes(&reply.lines) {
                                Ok(verified) => verified,
                                Err(_) => {
                                    return Ok(AdvertisementSetApplyResult::ambiguous(
                                        unreachable(),
                                    ));
                                }
                            },
                            Err(_) => {
                                return Ok(AdvertisementSetApplyResult::ambiguous(unreachable()));
                            }
                        };
                        if verified != accepted {
                            return Ok(AdvertisementSetApplyResult::ambiguous(unreachable()));
                        }
                    }
                    Ok(AdvertisementSetApplyResult::applied(outcomes))
                }
                Err(BirdCommandError::Io(_error)) => {
                    Ok(AdvertisementSetApplyResult::ambiguous(unreachable()))
                }
                Err(BirdCommandError::Refused(_code)) => {
                    Ok(AdvertisementSetApplyResult::ambiguous(unreachable()))
                }
            }
        })
        .await
    }

    async fn withdraw_all(&self, domain: RoutingDomainTag) -> Result<(), IpsecLbError> {
        self.withdraw_domains(&BTreeSet::from([domain])).await
    }

    async fn withdraw_domains(
        &self,
        domains: &BTreeSet<RoutingDomainTag>,
    ) -> Result<(), IpsecLbError> {
        if domains.is_empty()
            || domains.len() > MAX_ADVERTISEMENT_ROUTING_DOMAINS
            || domains.iter().any(|domain| self.binding(*domain).is_err())
        {
            return Err(IpsecLbError::invalid_config(
                "routing_domain",
                "withdrawal set is empty or contains an unmanaged domain",
            ));
        }
        let domains = domains.clone();
        let result = self
            .run_mutation("bird_withdraw_mutation", move |adapter| async move {
                let replacements = domains
                    .iter()
                    .map(|domain| (*domain, BTreeSet::new()))
                    .collect();
                let result = adapter.replace_fragments(&replacements, false).await?;
                match result {
                    FragmentApply::Replied(_code) => {
                        let names = domains
                            .iter()
                            .map(|domain| {
                                adapter
                                    .binding(*domain)
                                    .map(|binding| binding.static_protocol.clone())
                            })
                            .collect::<Result<BTreeSet<_>, _>>()?;
                        adapter
                            .await_protocols_absent(&names, "bird_withdraw_readback")
                            .await
                    }
                    FragmentApply::Ambiguous => Err(IpsecLbError::io(
                        "bird_configure",
                        io::Error::other("BIRD configure command result is unknown"),
                    )),
                    FragmentApply::Refused(_code) => Err(IpsecLbError::io(
                        "bird_configure",
                        io::Error::other("BIRD refused the reconfiguration"),
                    )),
                }
            })
            .await;
        if result.is_err() {
            self.lifecycle.request_fail_stop();
        }
        result
    }

    async fn poll_observations(&self) -> Result<Vec<PeerObservation>, IpsecLbError> {
        let protocols_reply =
            self.command("show protocols all")
                .await
                .map_err(|error| match error {
                    BirdCommandError::Io(error) => error,
                    BirdCommandError::Refused(_code) => IpsecLbError::io(
                        "bird_show_protocols",
                        io::Error::other("BIRD refused show protocols all"),
                    ),
                })?;
        // BFD reporting is optional: a daemon without a BFD protocol answers
        // with an error reply, which must not blind session telemetry. A
        // failed read briefly degrades to the last successfully read health
        // table. The cache then ages out so stale health cannot persist.
        let bfd_health: BTreeMap<IpAddress, PathHealth> =
            match self.command("show bfd sessions").await {
                Ok(reply) => {
                    let fresh = parse_show_bfd_sessions(&reply.lines);
                    self.bfd_health_cache
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .replace(fresh, Instant::now())?
                }
                Err(_) => self
                    .bfd_health_cache
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .usable_or_expire(
                        Instant::now(),
                        self.config.command_timeout.saturating_mul(2),
                    ),
            };
        let protocols = parse_show_protocols_all(&protocols_reply.lines);
        let mut pending = Vec::new();
        let mut local_readback_domains = BTreeMap::<RoutingDomainTag, String>::new();
        for binding in &self.config.domains {
            for peer_name in &binding.peer_protocols {
                if let Some(protocol) = protocols.iter().find(|p| &p.name == peer_name) {
                    let peer = PeerIdentity::named(protocol.name.clone());
                    let peer = match protocol.neighbor_address {
                        Some(address) => peer.with_address(address),
                        None => peer,
                    };
                    let path_health = protocol
                        .neighbor_address
                        .and_then(|address| bfd_health.get(&address).copied())
                        .unwrap_or(PathHealth::Unknown);
                    if protocol.session == PeerSessionState::Established {
                        local_readback_domains
                            .entry(binding.domain)
                            .or_insert_with(|| binding.static_protocol.clone());
                    }
                    pending.push((
                        binding.domain,
                        peer,
                        protocol.session,
                        path_health,
                        binding.static_protocol.clone(),
                    ));
                }
            }
        }

        enum RouteReadback {
            Local(RoutingDomainTag, BTreeSet<HostPrefix>),
            Peer(RoutingDomainTag, String, BTreeSet<HostPrefix>),
        }

        // BIRD configuration admission caps this to at most 64 tasks: one
        // local-origin readback per active domain plus one exact export view
        // per established peer. All commands run in one bounded wave and each
        // retains the adapter's command timeout.
        let mut readbacks = tokio::task::JoinSet::new();
        for (domain, static_protocol) in local_readback_domains {
            let adapter = self.clone();
            readbacks.spawn(async move {
                let reply = adapter
                    .command(&format!("show route protocol {static_protocol}"))
                    .await
                    .map_err(bird_observation_error)?;
                let prefixes = parse_show_route_host_prefixes(&reply.lines)?;
                Ok::<RouteReadback, IpsecLbError>(RouteReadback::Local(domain, prefixes))
            });
        }
        for (domain, peer, session, _path_health, static_protocol) in &pending {
            if *session != PeerSessionState::Established {
                continue;
            }
            let adapter = self.clone();
            let domain = *domain;
            let peer_name = peer.name().to_owned();
            let static_protocol = static_protocol.clone();
            readbacks.spawn(async move {
                let reply = adapter
                    .command(&format!(
                        "show route exported {peer_name} protocol {static_protocol}"
                    ))
                    .await
                    .map_err(bird_observation_error)?;
                let prefixes = parse_show_route_host_prefixes(&reply.lines)?;
                Ok::<RouteReadback, IpsecLbError>(RouteReadback::Peer(domain, peer_name, prefixes))
            });
        }

        let mut locally_originated = BTreeMap::<RoutingDomainTag, BTreeSet<HostPrefix>>::new();
        let mut peer_exports = BTreeMap::<(RoutingDomainTag, String), BTreeSet<HostPrefix>>::new();
        while let Some(result) = readbacks.join_next().await {
            let result = result.map_err(|_| {
                IpsecLbError::io(
                    "bird_route_readback_worker",
                    io::Error::other("BIRD route readback worker failed"),
                )
            })??;
            match result {
                RouteReadback::Local(domain, prefixes) => {
                    locally_originated.insert(domain, prefixes);
                }
                RouteReadback::Peer(domain, name, prefixes) => {
                    peer_exports.insert((domain, name), prefixes);
                }
            }
        }

        let mut observations = Vec::with_capacity(pending.len());
        for (domain, peer, session, path_health, _static_protocol) in pending {
            let advertised_prefixes = if session == PeerSessionState::Established {
                let local = locally_originated.get(&domain).ok_or_else(|| {
                    IpsecLbError::adapter_contract_violation("bird_missing_local_origin_readback")
                })?;
                let exported = peer_exports
                    .remove(&(domain, peer.name().to_owned()))
                    .ok_or_else(|| {
                        IpsecLbError::adapter_contract_violation(
                            "bird_missing_peer_export_readback",
                        )
                    })?;
                if !exported.is_subset(local) {
                    return Err(IpsecLbError::adapter_contract_violation(
                        "bird_exported_prefix_not_locally_originated",
                    ));
                }
                exported
            } else {
                BTreeSet::new()
            };
            observations.push(PeerObservation {
                domain,
                peer,
                session,
                path_health,
                advertised_prefixes,
            });
        }
        Ok(observations)
    }

    async fn probe(&self) -> Result<RoutingStackProbe, IpsecLbError> {
        let lifecycle_live = self.lifecycle.is_live();
        if !lifecycle_live {
            return Ok(RoutingStackProbe {
                kind: RoutingStackKind::Bird,
                stack_reachable: false,
                mutation_ready: false,
                details: Some("supervised BIRD process is not live".to_owned()),
                process_supervision_ready: false,
            });
        }
        match self.command("show status").await {
            Ok(_reply) => Ok(RoutingStackProbe {
                kind: RoutingStackKind::Bird,
                stack_reachable: true,
                mutation_ready: true,
                details: Some("BIRD control socket reachable".to_owned()),
                process_supervision_ready: true,
            }),
            Err(_error) => Ok(RoutingStackProbe {
                kind: RoutingStackKind::Bird,
                stack_reachable: false,
                mutation_ready: false,
                details: Some("BIRD control socket unreachable".to_owned()),
                process_supervision_ready: self.lifecycle.is_live(),
            }),
        }
    }
}

impl fmt::Display for BirdControlSocketAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bird-control-socket(domains={})",
            self.config.domains.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::AdvertisementSetDisposition;
    use std::sync::{Arc, Mutex};
    use tokio::net::UnixListener;

    fn binding() -> BirdDomainBinding {
        BirdDomainBinding {
            domain: RoutingDomainTag::new(64512),
            static_protocol: "opc_adv_64512".to_owned(),
            peer_protocols: vec!["edge_a".to_owned(), "edge_b".to_owned()],
        }
    }

    fn test_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("opc-ipsec-lb-bird-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn config(dir: &std::path::Path) -> BirdAdapterConfig {
        use std::os::unix::fs::PermissionsExt;

        let fragment_dir = dir.join("opc.d");
        std::fs::create_dir_all(&fragment_dir).unwrap();
        std::fs::set_permissions(&fragment_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        BirdAdapterConfig {
            socket_path: dir.join("bird.ctl"),
            fragment_dir,
            domains: vec![binding()],
            command_timeout: Duration::from_secs(5),
        }
    }

    type ScriptMap = Arc<Mutex<BTreeMap<String, Vec<String>>>>;

    fn script_map(pairs: &[(&str, &[&str])]) -> ScriptMap {
        Arc::new(Mutex::new(
            pairs
                .iter()
                .map(|(command, lines)| {
                    (
                        (*command).to_owned(),
                        lines.iter().map(|line| (*line).to_owned()).collect(),
                    )
                })
                .collect(),
        ))
    }

    /// A minimal BIRD-faithful control-socket server: sends the greeting,
    /// then answers each read line with the scripted raw reply bytes from
    /// the shared script map (tests may rewrite scripts between calls).
    async fn spawn_mock_bird(
        socket_path: PathBuf,
        scripts: ScriptMap,
    ) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(&socket_path).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let scripts = Arc::clone(&scripts);
                tokio::spawn(async move {
                    let (read_half, mut write_half) = stream.into_split();
                    let mut reader = BufReader::new(read_half);
                    write_half
                        .write_all(b"0001 BIRD 2.13 ready.\n")
                        .await
                        .unwrap();
                    let mut command = String::new();
                    loop {
                        command.clear();
                        let Ok(read) = reader.read_line(&mut command).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        let key = command.trim_end().to_owned();
                        let reply = scripts
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .get(&key)
                            .cloned();
                        let Some(reply_lines) = reply else {
                            write_half
                                .write_all(b"9002 unimplemented command \n")
                                .await
                                .unwrap();
                            continue;
                        };
                        for line in reply_lines {
                            write_half.write_all(line.as_bytes()).await.unwrap();
                        }
                    }
                });
            }
        })
    }

    #[tokio::test]
    async fn show_completes_on_real_bird_final_reply_framing() {
        // The real BIRD terminator is `0000 \n`: a code, a space, empty text.
        // Whitespace-trimming readers destroy the separator and hang.
        let dir = test_dir("final-framing");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let scripts = script_map(&[(
            "show status",
            &[
                "1000-BIRD 2.13\n",
                "1011-Router ID is 192.0.2.2\n",
                "0000 \n",
            ],
        )]);
        let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
        let adapter = BirdControlSocketAdapter::new_for_conformance(config(&dir)).unwrap();

        let probe = adapter.probe().await.unwrap();
        assert!(probe.stack_reachable);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn poll_parses_real_collapsed_framing_and_bfd_rows() {
        // Real BIRD collapses a repeated continuation code to a single space
        // plus the original text; `show bfd sessions` rows use code 1020.
        let dir = test_dir("collapsed-rows");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let scripts = script_map(&[
            (
                "show protocols all",
                &[
                    "2002-Name       Proto      Table      State  Since         Info\n",
                    "1002-device1    Device     ---        up     2024-01-01\n",
                    " edge_a     BGP        ---        up     10:00:00      Established\n",
                    "   Description:    upstream edge a\n",
                    "   BGP state:          Established\n",
                    "     Neighbor address: fe80::1%eth0\n",
                    "     Neighbor AS:      64512\n",
                    " edge_b     BGP        ---        up     10:00:01      Active\n",
                    "     Neighbor address: 203.0.113.2\n",
                    "     Neighbor AS:      64513\n",
                    "0000 \n",
                ],
            ),
            (
                "show bfd sessions",
                &[
                    "1020-bfd1:\n",
                    " IP address                Interface  State      Since         Interval  Timeout\n",
                    " fe80::1%eth0              eth0       Up         10:00:00.000  0.050     0.250\n",
                    " 203.0.113.2               eth0       Down       10:00:00.000  0.050     0.250\n",
                    "0000 \n",
                ],
            ),
            (
                "show route protocol opc_adv_64512",
                &[
                    "1008-Table master4:\n",
                    " 203.0.113.10/32 blackhole [opc_adv_64512 10:00:00] * (200)\n",
                    "0000 \n",
                ],
            ),
            (
                "show route exported edge_a protocol opc_adv_64512",
                &[
                    "1008-Table master4:\n",
                    " 203.0.113.10/32 blackhole [opc_adv_64512 10:00:00] * (200)\n",
                    "0000 \n",
                ],
            ),
        ]);
        let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
        let adapter = BirdControlSocketAdapter::new_for_conformance(config(&dir)).unwrap();

        let observations = adapter.poll_observations().await.unwrap();
        assert_eq!(observations.len(), 2);
        let edge_a = observations
            .iter()
            .find(|obs| obs.peer.name() == "edge_a")
            .unwrap();
        assert_eq!(edge_a.session, PeerSessionState::Established);
        assert_eq!(edge_a.path_health, PathHealth::Up);
        assert_eq!(
            edge_a.peer.address(),
            Some(IpAddress::V6([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ]))
        );
        assert_eq!(
            edge_a.advertised_prefixes,
            BTreeSet::from([HostPrefix::new(IpAddress::V4([203, 0, 113, 10]))])
        );
        let edge_b = observations
            .iter()
            .find(|obs| obs.peer.name() == "edge_b")
            .unwrap();
        assert_eq!(edge_b.session, PeerSessionState::Connecting);
        assert_eq!(edge_b.path_health, PathHealth::Down);
        assert!(edge_b.advertised_prefixes.is_empty());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn poll_reports_the_exact_independent_export_view_for_each_peer() {
        let dir = test_dir("exact-peer-exports");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let protocols = [
            "2002-Name       Proto      Table      State  Since         Info\n",
            "1002-edge_a     BGP        ---        up     10:00:00      Established\n",
            "     Neighbor address: 203.0.113.1\n",
            "1002-edge_b     BGP        ---        up     10:00:00      Established\n",
            "     Neighbor address: 203.0.113.2\n",
            "0000 \n",
        ];
        let local = [
            "1008-Table master4:\n",
            " 203.0.113.10/32 blackhole [opc_adv_64512 10:00:00] * (200)\n",
            " 203.0.113.11/32 blackhole [opc_adv_64512 10:00:00] * (200)\n",
            "0000 \n",
        ];
        let scripts = script_map(&[
            ("show protocols all", &protocols),
            ("show bfd sessions", &["0000 \n"]),
            ("show route protocol opc_adv_64512", &local),
            (
                "show route exported edge_a protocol opc_adv_64512",
                &[
                    "1008-Table master4:\n",
                    " 203.0.113.10/32 blackhole [opc_adv_64512 10:00:00] * (200)\n",
                    "0000 \n",
                ],
            ),
            (
                "show route exported edge_b protocol opc_adv_64512",
                &[
                    "1008-Table master4:\n",
                    " 203.0.113.11/32 blackhole [opc_adv_64512 10:00:00] * (200)\n",
                    "0000 \n",
                ],
            ),
        ]);
        let _server = spawn_mock_bird(dir.join("bird.ctl"), Arc::clone(&scripts)).await;
        let adapter = BirdControlSocketAdapter::new_for_conformance(config(&dir)).unwrap();

        let observations = adapter.poll_observations().await.unwrap();
        let by_name = |name: &str| {
            observations
                .iter()
                .find(|observation| observation.peer.name() == name)
                .unwrap()
        };
        assert_eq!(
            by_name("edge_a").advertised_prefixes,
            BTreeSet::from([HostPrefix::new(IpAddress::V4([203, 0, 113, 10]))])
        );
        assert_eq!(
            by_name("edge_b").advertised_prefixes,
            BTreeSet::from([HostPrefix::new(IpAddress::V4([203, 0, 113, 11]))])
        );

        // A locally originated route can be filtered out of one peer's
        // Adj-RIB-Out. Exact export readback must then report an empty set.
        scripts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                "show route exported edge_a protocol opc_adv_64512".to_owned(),
                vec!["1008-Table master4:\n".to_owned(), "0000 \n".to_owned()],
            );
        let observations = adapter.poll_observations().await.unwrap();
        assert!(observations
            .iter()
            .find(|observation| observation.peer.name() == "edge_a")
            .unwrap()
            .advertised_prefixes
            .is_empty());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn poll_rejects_an_exported_prefix_absent_from_local_origination() {
        let dir = test_dir("impossible-peer-export");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let mut adapter_config = config(&dir);
        adapter_config.domains[0].peer_protocols = vec!["edge_a".to_owned()];
        let scripts = script_map(&[
            (
                "show protocols all",
                &[
                    "2002-Name       Proto      Table      State  Since         Info\n",
                    "1002-edge_a     BGP        ---        up     10:00:00      Established\n",
                    "0000 \n",
                ],
            ),
            ("show bfd sessions", &["0000 \n"]),
            (
                "show route protocol opc_adv_64512",
                &[
                    "1008-Table master4:\n",
                    " 203.0.113.10/32 blackhole [opc_adv_64512 10:00:00] * (200)\n",
                    "0000 \n",
                ],
            ),
            (
                "show route exported edge_a protocol opc_adv_64512",
                &[
                    "1008-Table master4:\n",
                    " 203.0.113.11/32 blackhole [opc_adv_64512 10:00:00] * (200)\n",
                    "0000 \n",
                ],
            ),
        ]);
        let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
        let adapter = BirdControlSocketAdapter::new_for_conformance(adapter_config).unwrap();
        assert!(adapter.poll_observations().await.is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn bfd_health_cache_survives_transient_command_failure() {
        let dir = test_dir("bfd-cache");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let scripts = script_map(&[
            (
                "show protocols all",
                &[
                    "2002-Name       Proto      Table      State  Since         Info\n",
                    "1002-edge_a     BGP        ---        up     10:00:00      Established\n",
                    "     Neighbor address: 203.0.113.1\n",
                    "0000 \n",
                ],
            ),
            (
                "show bfd sessions",
                &[
                    "1020-bfd1:\n",
                    " 203.0.113.1               eth0       Up         10:00:00.000  0.050     0.250\n",
                    "0000 \n",
                ],
            ),
            (
                "show route protocol opc_adv_64512",
                &[
                    "1008-Table master4:\n",
                    " 203.0.113.10/32 blackhole [opc_adv_64512 10:00:00] * (200)\n",
                    "0000 \n",
                ],
            ),
            (
                "show route exported edge_a protocol opc_adv_64512",
                &[
                    "1008-Table master4:\n",
                    " 203.0.113.10/32 blackhole [opc_adv_64512 10:00:00] * (200)\n",
                    "0000 \n",
                ],
            ),
        ]);
        let _server = spawn_mock_bird(dir.join("bird.ctl"), Arc::clone(&scripts)).await;
        let adapter = BirdControlSocketAdapter::new_for_conformance(config(&dir)).unwrap();

        let observations = adapter.poll_observations().await.unwrap();
        assert_eq!(observations[0].path_health, PathHealth::Up);

        // The BFD command now fails (unimplemented): the last known health
        // is served from the cache instead of flapping to Unknown.
        scripts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove("show bfd sessions");
        let observations = adapter.poll_observations().await.unwrap();
        assert_eq!(observations[0].path_health, PathHealth::Up);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn adapter_debug_redacts_cached_bfd_peer_addresses() {
        let dir = test_dir("bfd-cache-debug-redaction");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let adapter = BirdControlSocketAdapter::new_for_conformance(config(&dir)).unwrap();
        adapter
            .bfd_health_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .replace(
                BTreeMap::from([(IpAddress::V4([198, 51, 100, 77]), PathHealth::Up)]),
                Instant::now(),
            )
            .unwrap();

        let rendered = format!("{adapter:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("198.51.100.77"));
        assert!(!rendered.contains("198, 51, 100, 77"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn configure_reply_codes_classify_success_ambiguous_and_refused() {
        let desired: BTreeSet<HostPrefix> = [HostPrefix::new(IpAddress::V4([203, 0, 113, 10]))]
            .into_iter()
            .collect();

        // 0003 Reconfigured + show route verifies the prefix: Accepted.
        let dir = test_dir("configure-success");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let scripts = script_map(&[
            (
                "configure soft",
                &["0002-Reading configuration\n", "0003 Reconfigured\n"],
            ),
            (
                "show route protocol opc_adv_64512",
                &[
                    "1008-Table master4:\n",
                    " 203.0.113.10/32    blackhole [opc_adv_64512 10:00:00] * (200)\n",
                    "0000 \n",
                ],
            ),
        ]);
        let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
        let adapter = BirdControlSocketAdapter::new_for_conformance(config(&dir)).unwrap();
        let outcomes = adapter
            .apply_advertisement_set(binding().domain, &desired)
            .await
            .unwrap();
        assert_eq!(outcomes.disposition, AdvertisementSetDisposition::Applied);
        assert_eq!(
            outcomes.outcomes.values().collect::<Vec<_>>(),
            vec![&PrefixApplyOutcome::Accepted]
        );
        // The fragment landed atomically: no temporary file remains.
        assert!(dir.join("opc.d/opc-ipsec-lb-domain-64512.conf").exists());
        assert!(!dir.join("opc.d/opc-ipsec-lb-domain-64512.tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();

        // 0004 Reconfiguration in progress: ambiguous, never a rejection.
        let dir = test_dir("configure-queued");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let scripts = script_map(&[("configure soft", &["0004 Reconfiguration in progress\n"])]);
        let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
        let adapter = BirdControlSocketAdapter::new_for_conformance(config(&dir)).unwrap();
        let outcomes = adapter
            .apply_advertisement_set(binding().domain, &desired)
            .await
            .unwrap();
        assert_eq!(outcomes.disposition, AdvertisementSetDisposition::Ambiguous);
        assert!(!dir.join("opc.d/opc-ipsec-lb-domain-64512.conf").exists());
        assert_eq!(
            outcomes.outcomes.values().collect::<Vec<_>>(),
            vec![&PrefixApplyOutcome::Unreachable]
        );
        std::fs::remove_dir_all(&dir).unwrap();

        // 9xxx refusal: the only ConfigureFailed path.
        let dir = test_dir("configure-refused");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let scripts = script_map(&[("configure soft", &["9001 Parse error\n"])]);
        let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
        let adapter = BirdControlSocketAdapter::new_for_conformance(config(&dir)).unwrap();
        let outcomes = adapter
            .apply_advertisement_set(binding().domain, &desired)
            .await
            .unwrap();
        assert_eq!(outcomes.disposition, AdvertisementSetDisposition::Refused);
        assert!(!dir.join("opc.d/opc-ipsec-lb-domain-64512.conf").exists());
        assert_eq!(
            outcomes.outcomes.values().collect::<Vec<_>>(),
            vec![&PrefixApplyOutcome::Rejected(
                PrefixRejectReason::ConfigureFailed
            )]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn mid_command_disconnect_is_unreachable_not_rejected() {
        // The server accepts the configure command and then drops the
        // connection without any reply: BIRD may have applied the fragment.
        let dir = test_dir("mid-command-eof");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let previous = render_fragment(
            &binding(),
            &[HostPrefix::new(IpAddress::V4([203, 0, 113, 20]))]
                .into_iter()
                .collect(),
        );
        std::fs::write(dir.join("opc.d/opc-ipsec-lb-domain-64512.conf"), &previous).unwrap();
        let listener = UnixListener::bind(dir.join("bird.ctl")).unwrap();
        let _server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let (read_half, mut write_half) = stream.into_split();
                    let mut reader = BufReader::new(read_half);
                    write_half
                        .write_all(b"0001 BIRD 2.13 ready.\n")
                        .await
                        .unwrap();
                    let mut command = String::new();
                    let _ = reader.read_line(&mut command).await;
                    // Drop the connection mid-command without a reply.
                });
            }
        });
        let adapter = BirdControlSocketAdapter::new_for_conformance(config(&dir)).unwrap();
        let desired: BTreeSet<HostPrefix> = [HostPrefix::new(IpAddress::V4([203, 0, 113, 10]))]
            .into_iter()
            .collect();
        let outcomes = adapter
            .apply_advertisement_set(binding().domain, &desired)
            .await
            .unwrap();
        assert_eq!(outcomes.disposition, AdvertisementSetDisposition::Ambiguous);
        assert_eq!(
            std::fs::read_to_string(dir.join("opc.d/opc-ipsec-lb-domain-64512.conf")).unwrap(),
            previous
        );
        assert_eq!(
            outcomes.outcomes.values().collect::<Vec<_>>(),
            vec![&PrefixApplyOutcome::Unreachable]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reply_line_classification_handles_real_bird_framing() {
        let mut last_code = 0u16;
        assert_eq!(
            classify_reply_line("0001 BIRD 2.13 ready.", &mut last_code),
            ReplyLine::Final(1, "BIRD 2.13 ready.".to_owned())
        );
        assert_eq!(
            classify_reply_line("2002-Name       Proto", &mut last_code),
            ReplyLine::Content("Name       Proto".to_owned())
        );
        // Real code-collapse: a single space plus the original text.
        assert_eq!(
            classify_reply_line(" edge_a     BGP", &mut last_code),
            ReplyLine::Content("edge_a     BGP".to_owned())
        );
        assert_eq!(
            classify_reply_line("   Description:    upstream", &mut last_code),
            ReplyLine::Content("  Description:    upstream".to_owned())
        );
        // The real terminator: code, space, empty text.
        assert_eq!(
            classify_reply_line("0000 ", &mut last_code),
            ReplyLine::Final(0, String::new())
        );
        // A bare final reply without the trailing separator.
        assert_eq!(
            classify_reply_line("0000", &mut last_code),
            ReplyLine::Final(0, String::new())
        );
        // Reading configuration is progress, never the final reply.
        assert_eq!(
            classify_reply_line("0002 Reading configuration", &mut last_code),
            ReplyLine::Progress
        );
        assert_eq!(
            classify_reply_line("0003 Reconfigured", &mut last_code),
            ReplyLine::Final(3, "Reconfigured".to_owned())
        );
        assert_eq!(
            classify_reply_line("not a reply", &mut last_code),
            ReplyLine::Content("not a reply".to_owned())
        );
    }

    #[test]
    fn fragment_renders_exact_desired_set_per_family() {
        let desired: BTreeSet<HostPrefix> = [
            HostPrefix::new(IpAddress::V4([203, 0, 113, 10])),
            HostPrefix::new(IpAddress::V4([198, 51, 100, 7])),
            HostPrefix::new(IpAddress::V6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
            ])),
        ]
        .into_iter()
        .collect();
        let fragment = render_fragment(&binding(), &desired);
        assert!(fragment.contains("protocol static opc_adv_64512 {"));
        assert!(fragment.contains("route 203.0.113.10/32 blackhole;"));
        assert!(fragment.contains("route 198.51.100.7/32 blackhole;"));
        assert!(fragment.contains("route 2001:db8::7/128 blackhole;"));
        assert!(!fragment.contains("10.0.0.0"));
    }

    #[test]
    fn owned_fragment_parser_accepts_only_the_complete_canonical_grammar() {
        let desired: BTreeSet<HostPrefix> = [
            HostPrefix::new(IpAddress::V4([203, 0, 113, 10])),
            HostPrefix::new(IpAddress::V6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
            ])),
        ]
        .into_iter()
        .collect();
        let fragment = render_fragment(&binding(), &desired);
        assert_eq!(
            parse_owned_fragment(&fragment, binding().domain).unwrap(),
            binding().static_protocol
        );

        for malformed in [
            fragment.replace(
                "    route 203.0.113.10/32 blackhole;",
                "    route 203.0.113.0/24 blackhole;",
            ),
            fragment.replace(
                "    route 203.0.113.10/32 blackhole;",
                "    route 203.0.113.10/32 blackhole;\n    import all;",
            ),
            format!("{fragment}# trailing injected content\n"),
            fragment.replace("    ipv4;", "    ipv6;"),
        ] {
            assert!(parse_owned_fragment(&malformed, binding().domain).is_err());
        }
    }

    #[tokio::test]
    async fn pre_spawn_cleanup_validates_and_removes_the_complete_owned_namespace() {
        let dir = test_dir("pre-spawn-cleanup");
        let adapter_config = config(&dir);
        let canonical = fragment_file_name(binding().domain);
        let temporary = legacy_fragment_temp_name(RoutingDomainTag::new(64_513));
        std::fs::write(
            adapter_config.fragment_dir.join(&canonical),
            render_fragment(
                &binding(),
                &[HostPrefix::new(IpAddress::V4([203, 0, 113, 10]))]
                    .into_iter()
                    .collect(),
            ),
        )
        .unwrap();
        std::fs::write(adapter_config.fragment_dir.join(&temporary), b"partial").unwrap();

        let namespace = Arc::new(FragmentNamespace::open(&adapter_config.fragment_dir).unwrap());
        namespace.clear_owned_before_spawn_sync().unwrap();
        assert!(!adapter_config.fragment_dir.join(canonical).exists());
        assert!(!adapter_config.fragment_dir.join(temporary).exists());
        drop(namespace);
        std::fs::remove_dir_all(&dir).unwrap();

        let dir = test_dir("pre-spawn-malformed");
        let adapter_config = config(&dir);
        let canonical = fragment_file_name(binding().domain);
        std::fs::write(
            adapter_config.fragment_dir.join(&canonical),
            format!(
                "{}    import all;\n}}\n",
                render_fragment(&binding(), &BTreeSet::new()).trim_end_matches("}\n")
            ),
        )
        .unwrap();
        let namespace = Arc::new(FragmentNamespace::open(&adapter_config.fragment_dir).unwrap());
        assert!(namespace.clear_owned_before_spawn_sync().is_err());
        assert!(adapter_config.fragment_dir.join(canonical).exists());
        drop(namespace);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn pre_spawn_blocking_work_obeys_the_startup_deadline() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let finished = Arc::new(AtomicBool::new(false));
        let worker_release = Arc::clone(&release);
        let worker_finished = Arc::clone(&finished);
        let result = run_bounded_startup_blocking(
            Duration::from_millis(10),
            "synthetic_pre_spawn",
            move || {
                let (lock, wake) = &*worker_release;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = wake.wait(released).unwrap();
                }
                worker_finished.store(true, Ordering::Release);
                Ok(())
            },
        )
        .await;
        assert!(result.is_err());

        let (lock, wake) = &*release;
        *lock.lock().unwrap() = true;
        wake.notify_one();
        for _ in 0..100 {
            if finished.load(Ordering::Acquire) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert!(finished.load(Ordering::Acquire));
    }

    #[test]
    fn show_protocols_all_parses_transient_states_and_neighbor_addresses() {
        let output: Vec<String> = [
            "Name       Proto      Table      State  Since         Info",
            "device1    Device     ---        up     2024-01-01",
            "edge_a     BGP        ---        up     10:00:00      Established",
            "  Description:    upstream edge a",
            "  BGP state:          Established",
            "    Neighbor address: 203.0.113.1",
            "    Neighbor AS:      64512",
            "edge_b     BGP        ---        up     2024-01-01 10:00:01  Active",
            "    Neighbor address: 203.0.113.2",
            "    Neighbor AS:      64513",
            "edge_c     BGP        ---        start  10:00:02",
            "kernel1    Kernel     master4    up     2024-01-01",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        let protocols = parse_show_protocols_all(&output);
        let by_name = |name: &str| protocols.iter().find(|p| p.name == name).unwrap();
        assert_eq!(by_name("edge_a").session, PeerSessionState::Established);
        assert_eq!(
            by_name("edge_a").neighbor_address,
            Some(IpAddress::V4([203, 0, 113, 1]))
        );
        // A space-containing Since column does not break keyword scanning.
        assert_eq!(by_name("edge_b").session, PeerSessionState::Connecting);
        // Transient protocol states classify as down instead of vanishing.
        assert_eq!(by_name("edge_c").session, PeerSessionState::Down);
    }

    #[test]
    fn show_bfd_sessions_parses_real_table_format() {
        let output: Vec<String> = [
            "bfd1:",
            "IP address                Interface  State      Since         Interval  Timeout",
            "203.0.113.1               eth0       Up         10:00:00.000  0.050     0.250",
            "203.0.113.2               eth0       Down       10:00:00.000  0.050     0.250",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        let rows = parse_show_bfd_sessions(&output);
        assert_eq!(
            rows.get(&IpAddress::V4([203, 0, 113, 1])),
            Some(&PathHealth::Up)
        );
        assert_eq!(
            rows.get(&IpAddress::V4([203, 0, 113, 2])),
            Some(&PathHealth::Down)
        );
    }

    #[test]
    fn duplicate_bfd_sessions_fold_to_the_worst_state() {
        let output: Vec<String> = [
            "203.0.113.1               eth0       Up         10:00:00.000  0.050     0.250",
            "203.0.113.1               eth1       Down       10:00:00.000  0.050     0.250",
            "203.0.113.2               eth0       Up         10:00:00.000  0.050     0.250",
            "203.0.113.2               eth1       Up         10:00:00.000  0.050     0.250",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        let rows = parse_show_bfd_sessions(&output);
        assert_eq!(
            rows.get(&IpAddress::V4([203, 0, 113, 1])),
            Some(&PathHealth::Down)
        );
        assert_eq!(
            rows.get(&IpAddress::V4([203, 0, 113, 2])),
            Some(&PathHealth::Up)
        );
    }

    #[test]
    fn link_local_bfd_neighbor_zone_suffix_is_dropped() {
        let output: Vec<String> =
            ["fe80::1%eth0                  eth0       Up         10:00:00.000  0.050     0.250"]
                .iter()
                .map(ToString::to_string)
                .collect();
        let rows = parse_show_bfd_sessions(&output);
        let link_local = IpAddress::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(rows.get(&link_local), Some(&PathHealth::Up));
    }

    #[test]
    fn bfd_cache_is_bounded_and_ages_to_unknown() {
        let now = Instant::now();
        let neighbor = IpAddress::V4([203, 0, 113, 1]);
        let mut cache = BfdHealthCache::default();
        cache
            .replace(BTreeMap::from([(neighbor, PathHealth::Up)]), now)
            .unwrap();
        assert_eq!(
            cache.usable_or_expire(now + Duration::from_secs(1), Duration::from_secs(2)),
            BTreeMap::from([(neighbor, PathHealth::Up)])
        );
        assert!(cache
            .usable_or_expire(now + Duration::from_secs(3), Duration::from_secs(2))
            .is_empty());

        let overflow: BTreeMap<IpAddress, PathHealth> = (0..=MAX_ROUTING_PEERS_TOTAL)
            .map(|index| {
                let mut octets = [0_u8; 16];
                octets[8..].copy_from_slice(&(index as u64).to_be_bytes());
                (IpAddress::V6(octets), PathHealth::Up)
            })
            .collect();
        assert!(cache.replace(overflow, now).is_err());
        assert!(cache.health.is_empty());
    }

    #[test]
    fn fragment_namespace_rejects_public_directories_and_symlink_candidates() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = test_dir("descriptor-namespace");
        let private = root.join("private");
        std::fs::create_dir_all(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let namespace = FragmentNamespace::open(&private).unwrap();
        assert!(
            FragmentNamespace::open(&private).is_err(),
            "a second adapter cannot concurrently own the fragment namespace"
        );

        let target = root.join("outside-target");
        std::fs::write(&target, b"outside").unwrap();
        let candidate = fragment_file_name(binding().domain);
        symlink(&target, private.join(&candidate)).unwrap();
        assert!(namespace.read_sync(&candidate).is_err());
        assert!(namespace
            .write_atomic_sync(&candidate, b"replacement")
            .is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"outside");

        let public = root.join("public");
        std::fs::create_dir_all(&public).unwrap();
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(FragmentNamespace::open(&public).is_err());
        assert!(FragmentNamespace::open(Path::new("relative-fragments")).is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn fragment_namespace_rejects_a_canonical_fifo_without_blocking() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{mpsc, Barrier};

        use rustix::fs::{mkfifoat, Mode, OFlags, CWD};

        let root = test_dir("descriptor-fifo");
        let private = root.join("private");
        std::fs::create_dir_all(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let namespace = FragmentNamespace::open(&private).unwrap();
        let name = fragment_file_name(binding().domain);
        let fifo = private.join(&name);
        mkfifoat(CWD, &fifo, Mode::from_raw_mode(0o600)).unwrap();
        let started = Arc::new(Barrier::new(2));
        let worker_started = Arc::clone(&started);
        let worker_namespace = namespace.clone();
        let worker_name = name.clone();
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            worker_started.wait();
            let rejected = worker_namespace.read_sync(&worker_name).is_err();
            let _ = result_tx.send(rejected);
        });
        started.wait();

        let prompt_result = result_rx.recv_timeout(Duration::from_secs(1));
        if prompt_result.is_err() {
            // Unblock a regressed FIFO reader before failing, so no test
            // worker remains stranded in the process.
            let _release = rustix::fs::openat(
                CWD,
                &fifo,
                OFlags::RDWR | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            let _ = result_rx.recv_timeout(Duration::from_secs(1));
        }
        worker.join().unwrap();
        assert!(prompt_result.unwrap());
        assert!(namespace.inventory_sync().is_err());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn atomic_fragment_write_uses_exclusive_random_temporary_namespace() {
        use std::os::unix::fs::PermissionsExt;

        let root = test_dir("random-temporary");
        let private = root.join("private");
        std::fs::create_dir_all(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let namespace = FragmentNamespace::open(&private).unwrap();
        let name = fragment_file_name(binding().domain);

        namespace.write_atomic_sync(&name, b"complete").unwrap();
        assert_eq!(
            namespace.read_sync(&name).unwrap(),
            Some(b"complete".to_vec())
        );
        assert!(!private
            .join(legacy_fragment_temp_name(binding().domain))
            .exists());
        assert!(std::fs::read_dir(&private).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp.")));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn mutation_timeout_fail_stops_lifecycle_and_rejects_following_work() {
        let root = test_dir("late-mutation");
        let mut adapter_config = config(&root);
        adapter_config.command_timeout = Duration::from_millis(10);
        let adapter = BirdControlSocketAdapter::new_for_conformance(adapter_config).unwrap();
        let never_release = Arc::new(tokio::sync::Notify::new());
        let parked = Arc::clone(&never_release);

        let first = adapter
            .run_mutation("synthetic_first", move |_adapter| async move {
                parked.notified().await;
                Ok::<(), IpsecLbError>(())
            })
            .await;
        assert!(first.is_err());
        assert!(!adapter.lifecycle.is_live());

        let second = adapter
            .run_mutation("synthetic_second", move |_adapter| async move { Ok(()) })
            .await;
        assert!(second.is_err());

        never_release.notify_waiters();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn adapter_rejects_an_oversize_prefix_set_before_any_io() {
        let root = test_dir("public-prefix-bound");
        let adapter = BirdControlSocketAdapter::new_for_conformance(config(&root)).unwrap();
        let desired: BTreeSet<HostPrefix> = (0
            ..=crate::routing::MAX_ADVERTISED_PREFIXES_PER_DOMAIN)
            .map(|index| {
                let mut octets = [0_u8; 16];
                octets[8..].copy_from_slice(&(index as u64).to_be_bytes());
                HostPrefix::new(IpAddress::V6(octets))
            })
            .collect();

        assert!(adapter
            .apply_advertisement_set(binding().domain, &desired)
            .await
            .is_err());
        assert!(!root.join("bird.ctl").exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn fragment_batch_preflight_failure_cannot_partially_mutate_an_earlier_domain() {
        use std::os::unix::fs::symlink;

        let root = test_dir("batch-preflight");
        let mut adapter_config = config(&root);
        let second = BirdDomainBinding {
            domain: RoutingDomainTag::new(64_513),
            static_protocol: "opc_adv_64513".to_owned(),
            peer_protocols: Vec::new(),
        };
        adapter_config.domains.push(second.clone());
        let adapter = BirdControlSocketAdapter::new_for_conformance(adapter_config).unwrap();
        let first_name = fragment_file_name(binding().domain);
        let second_name = fragment_file_name(second.domain);
        let first_path = root.join("opc.d").join(&first_name);
        std::fs::write(&first_path, b"unchanged-before-preflight").unwrap();
        let outside = root.join("outside");
        std::fs::write(&outside, b"outside").unwrap();
        symlink(&outside, root.join("opc.d").join(second_name)).unwrap();
        let replacements = BTreeMap::from([
            (
                binding().domain,
                BTreeSet::from([HostPrefix::new(IpAddress::V4([203, 0, 113, 10]))]),
            ),
            (
                second.domain,
                BTreeSet::from([HostPrefix::new(IpAddress::V4([198, 51, 100, 10]))]),
            ),
        ]);

        assert!(adapter.apply_fragments(&replacements).await.is_err());
        assert_eq!(
            std::fs::read(&first_path).unwrap(),
            b"unchanged-before-preflight"
        );
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn show_route_parses_originated_prefixes() {
        let output: Vec<String> = [
            "Table master4:",
            "203.0.113.10/32    blackhole [opc_adv_64512 10:00:00] * (200)",
            "198.51.100.7/32    blackhole [opc_adv_64512 10:00:00] * (200)",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        let prefixes = parse_show_route_host_prefixes(&output).unwrap();
        assert!(prefixes.contains(&HostPrefix::new(IpAddress::V4([203, 0, 113, 10]))));
        assert!(prefixes.contains(&HostPrefix::new(IpAddress::V4([198, 51, 100, 7]))));
    }

    #[test]
    fn show_route_rejects_non_host_malformed_and_duplicate_prefixes() {
        for lines in [
            vec!["203.0.113.0/24 blackhole".to_owned()],
            vec!["203.0.113.10/32/extra blackhole".to_owned()],
            vec!["not-an-address/32 blackhole".to_owned()],
            vec![
                "203.0.113.10/32 blackhole".to_owned(),
                "203.0.113.10/32 blackhole".to_owned(),
            ],
        ] {
            assert!(parse_show_route_host_prefixes(&lines).is_err());
        }
    }

    #[tokio::test]
    async fn refused_or_queued_shrink_restores_the_previous_durable_fragment() {
        for (tag, reply, expected) in [
            (
                "shrink-refused",
                "9001 Parse error\n",
                AdvertisementSetDisposition::Refused,
            ),
            (
                "shrink-queued",
                "0004 Reconfiguration in progress\n",
                AdvertisementSetDisposition::Ambiguous,
            ),
        ] {
            let dir = test_dir(tag);
            std::fs::create_dir_all(dir.join("opc.d")).unwrap();
            let old: BTreeSet<HostPrefix> = [
                HostPrefix::new(IpAddress::V4([203, 0, 113, 10])),
                HostPrefix::new(IpAddress::V4([203, 0, 113, 11])),
            ]
            .into_iter()
            .collect();
            let new: BTreeSet<HostPrefix> = [HostPrefix::new(IpAddress::V4([203, 0, 113, 11]))]
                .into_iter()
                .collect();
            let old_fragment = render_fragment(&binding(), &old);
            std::fs::write(
                dir.join("opc.d/opc-ipsec-lb-domain-64512.conf"),
                old_fragment.as_bytes(),
            )
            .unwrap();
            let scripts = script_map(&[("configure soft", &[reply])]);
            let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
            let adapter = BirdControlSocketAdapter::new_for_conformance(config(&dir)).unwrap();

            let result = adapter
                .apply_advertisement_set(binding().domain, &new)
                .await
                .unwrap();
            assert_eq!(result.disposition, expected);
            assert_eq!(
                std::fs::read_to_string(dir.join("opc.d/opc-ipsec-lb-domain-64512.conf")).unwrap(),
                old_fragment
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[tokio::test]
    async fn every_unconfirmed_withdrawal_fail_stops_the_owned_routing_process() {
        for (tag, reply) in [
            ("withdraw-refused-fail-stop", "9001 Parse error\n"),
            (
                "withdraw-ambiguous-fail-stop",
                "0004 Reconfiguration in progress\n",
            ),
        ] {
            let dir = test_dir(tag);
            std::fs::create_dir_all(dir.join("opc.d")).unwrap();
            let fragment = dir.join("opc.d").join(fragment_file_name(binding().domain));
            std::fs::write(
                &fragment,
                render_fragment(
                    &binding(),
                    &[HostPrefix::new(IpAddress::V4([203, 0, 113, 10]))]
                        .into_iter()
                        .collect(),
                ),
            )
            .unwrap();
            let scripts = script_map(&[("configure soft", &[reply])]);
            let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
            let adapter = BirdControlSocketAdapter::new_for_conformance(config(&dir)).unwrap();

            assert!(adapter.withdraw_all(binding().domain).await.is_err());
            assert!(!adapter.lifecycle.is_live());
            let probe = adapter.probe().await.unwrap();
            assert!(!probe.process_supervision_ready);
            assert!(!probe.mutation_ready);
            assert!(
                !fragment.exists(),
                "failed withdrawal must not durably restore advertisement intent"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }

        let dir = test_dir("withdraw-readback-fail-stop");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let scripts = script_map(&[
            ("configure soft", &["0003 Reconfigured\n"]),
            (
                "show protocols all",
                &[
                    "2002-Name       Proto      Table      State  Since         Info\n",
                    "1002-opc_adv_64512 Static master4  up     10:00:00\n",
                    "0000 \n",
                ],
            ),
        ]);
        let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
        let mut adapter_config = config(&dir);
        adapter_config.command_timeout = Duration::from_millis(50);
        let adapter = BirdControlSocketAdapter::new_for_conformance(adapter_config).unwrap();
        assert!(adapter.withdraw_all(binding().domain).await.is_err());
        assert!(!adapter.lifecycle.is_live());
        std::fs::remove_dir_all(&dir).unwrap();

        let dir = test_dir("withdraw-readback-success");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let scripts = script_map(&[
            ("configure soft", &["0003 Reconfigured\n"]),
            (
                "show protocols all",
                &["2002-Name Proto Table State\n", "0000 \n"],
            ),
        ]);
        let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
        let adapter = BirdControlSocketAdapter::new_for_conformance(config(&dir)).unwrap();
        adapter.withdraw_all(binding().domain).await.unwrap();
        assert!(adapter.lifecycle.is_live());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn readback_rejected_prefix_is_removed_before_an_applied_result() {
        let dir = test_dir("accepted-subset");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let scripts = script_map(&[
            ("configure soft", &["0003 Reconfigured\n"]),
            (
                "show route protocol opc_adv_64512",
                &[
                    "1008-Table master4:\n",
                    " 203.0.113.10/32 blackhole [opc_adv_64512 10:00:00] * (200)\n",
                    "0000 \n",
                ],
            ),
        ]);
        let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
        let adapter = BirdControlSocketAdapter::new_for_conformance(config(&dir)).unwrap();
        let desired: BTreeSet<HostPrefix> = [
            HostPrefix::new(IpAddress::V4([203, 0, 113, 10])),
            HostPrefix::new(IpAddress::V4([203, 0, 113, 11])),
        ]
        .into_iter()
        .collect();

        let result = adapter
            .apply_advertisement_set(binding().domain, &desired)
            .await
            .unwrap();
        assert_eq!(result.disposition, AdvertisementSetDisposition::Applied);
        assert_eq!(
            result
                .outcomes
                .get(&HostPrefix::new(IpAddress::V4([203, 0, 113, 10]))),
            Some(&PrefixApplyOutcome::Accepted)
        );
        assert_eq!(
            result
                .outcomes
                .get(&HostPrefix::new(IpAddress::V4([203, 0, 113, 11]))),
            Some(&PrefixApplyOutcome::Rejected(
                PrefixRejectReason::StackRejected
            ))
        );
        let fragment =
            std::fs::read_to_string(dir.join("opc.d/opc-ipsec-lb-domain-64512.conf")).unwrap();
        assert!(fragment.contains("203.0.113.10/32"));
        assert!(!fragment.contains("203.0.113.11/32"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn control_reply_total_line_bound_is_enforced_during_read() {
        let dir = test_dir("reply-total-bound");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let mut lines = Vec::with_capacity(BIRD_REPLY_LINES_MAX + 2);
        lines.extend((0..=BIRD_REPLY_LINES_MAX).map(|_| "1000-row\n".to_owned()));
        lines.push("0000 \n".to_owned());
        let scripts = Arc::new(Mutex::new(BTreeMap::from([(
            "show status".to_owned(),
            lines,
        )])));
        let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
        let adapter = BirdControlSocketAdapter::new_for_conformance(config(&dir)).unwrap();

        let error = adapter.command("show status").await.unwrap_err();
        assert!(matches!(
            error,
            BirdCommandError::Io(IpsecLbError::Io { .. })
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn control_reply_total_byte_bound_is_enforced_during_read() {
        let dir = test_dir("reply-byte-bound");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let content = "x".repeat(BIRD_REPLY_LINE_MAX - 5);
        let lines_needed = BIRD_REPLY_BYTES_MAX
            .checked_div(content.len())
            .unwrap()
            .saturating_add(1);
        assert!(lines_needed < BIRD_REPLY_LINES_MAX);
        let mut lines = Vec::with_capacity(lines_needed + 1);
        lines.extend((0..lines_needed).map(|_| format!("1000-{content}\n")));
        lines.push("0000 \n".to_owned());
        let scripts = Arc::new(Mutex::new(BTreeMap::from([(
            "show status".to_owned(),
            lines,
        )])));
        let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
        let adapter = BirdControlSocketAdapter::new_for_conformance(config(&dir)).unwrap();

        let error = adapter.command("show status").await.unwrap_err();
        assert!(matches!(
            error,
            BirdCommandError::Io(IpsecLbError::Io { .. })
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn startup_discovers_removed_domain_fragment_and_proves_protocol_absence() {
        let dir = test_dir("startup-removed-domain");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let stale_binding = BirdDomainBinding {
            domain: RoutingDomainTag::new(64_513),
            static_protocol: "opc_adv_removed".to_owned(),
            peer_protocols: Vec::new(),
        };
        std::fs::write(
            dir.join("opc.d/opc-ipsec-lb-domain-64513.conf"),
            render_fragment(
                &stale_binding,
                &[HostPrefix::new(IpAddress::V4([203, 0, 113, 42]))]
                    .into_iter()
                    .collect(),
            ),
        )
        .unwrap();
        let scripts = script_map(&[
            ("configure soft", &["0003 Reconfigured\n"]),
            (
                "show protocols all",
                &[
                    "2002-Name       Proto      Table      State  Since         Info\n",
                    "1002-device1    Device     ---        up     10:00:00\n",
                    "0000 \n",
                ],
            ),
        ]);
        let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
        let adapter = BirdControlSocketAdapter::new_for_conformance(config(&dir)).unwrap();

        adapter.establish_known_absence().await.unwrap();

        assert!(!dir.join("opc.d/opc-ipsec-lb-domain-64513.conf").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn startup_fails_closed_on_malformed_or_overflow_owned_fragments() {
        let malformed_dir = test_dir("startup-malformed-owned");
        std::fs::create_dir_all(malformed_dir.join("opc.d")).unwrap();
        std::fs::write(
            malformed_dir.join("opc.d/opc-ipsec-lb-domain-64513.conf"),
            "# unknown-owned-version\n",
        )
        .unwrap();
        let adapter =
            BirdControlSocketAdapter::new_for_conformance(config(&malformed_dir)).unwrap();
        assert!(adapter.establish_known_absence().await.is_err());
        assert!(malformed_dir
            .join("opc.d/opc-ipsec-lb-domain-64513.conf")
            .exists());
        std::fs::remove_dir_all(&malformed_dir).unwrap();

        let overflow_dir = test_dir("startup-overflow-owned");
        std::fs::create_dir_all(overflow_dir.join("opc.d")).unwrap();
        for raw_domain in 1..=(MAX_ADVERTISEMENT_ROUTING_DOMAINS as u64 + 1) {
            let stale_binding = BirdDomainBinding {
                domain: RoutingDomainTag::new(raw_domain),
                static_protocol: format!("opc_stale_{raw_domain}"),
                peer_protocols: Vec::new(),
            };
            std::fs::write(
                overflow_dir
                    .join("opc.d")
                    .join(fragment_file_name(stale_binding.domain)),
                render_fragment(&stale_binding, &BTreeSet::new()),
            )
            .unwrap();
        }
        let adapter = BirdControlSocketAdapter::new_for_conformance(config(&overflow_dir)).unwrap();
        assert!(adapter.establish_known_absence().await.is_err());
        std::fs::remove_dir_all(&overflow_dir).unwrap();
    }

    #[tokio::test]
    async fn startup_fails_closed_when_removed_protocol_survives_reconfigure() {
        let dir = test_dir("startup-protocol-survives");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let stale_binding = BirdDomainBinding {
            domain: RoutingDomainTag::new(64_513),
            static_protocol: "opc_adv_removed".to_owned(),
            peer_protocols: Vec::new(),
        };
        std::fs::write(
            dir.join("opc.d/opc-ipsec-lb-domain-64513.conf"),
            render_fragment(&stale_binding, &BTreeSet::new()),
        )
        .unwrap();
        let scripts = script_map(&[
            ("configure soft", &["0003 Reconfigured\n"]),
            (
                "show protocols all",
                &[
                    "2002-Name       Proto      Table      State  Since         Info\n",
                    "1002-opc_adv_removed Static master4  up     10:00:00\n",
                    "0000 \n",
                ],
            ),
        ]);
        let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
        let adapter = BirdControlSocketAdapter::new_for_conformance(config(&dir)).unwrap();

        assert!(adapter.establish_known_absence().await.is_err());
        let probe = adapter.probe().await.unwrap();
        assert!(!probe.process_supervision_ready);
        assert!(!probe.stack_reachable);
        assert!(!probe.mutation_ready);
        assert!(adapter
            .apply_advertisement_set(binding().domain, &BTreeSet::new())
            .await
            .is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn config_validation_rejects_bad_symbols_and_duplicates() {
        let mut candidate = BirdAdapterConfig {
            socket_path: PathBuf::from("/run/bird/bird.ctl"),
            fragment_dir: PathBuf::from("/etc/bird/opc.d"),
            domains: vec![binding()],
            command_timeout: Duration::from_secs(10),
        };
        candidate.validate().unwrap();

        candidate.domains[0].static_protocol = "bad name;".to_owned();
        assert!(candidate.validate().is_err());
        candidate.domains[0].static_protocol = "opc_adv_64512".to_owned();

        candidate.domains.push(candidate.domains[0].clone());
        assert!(candidate.validate().is_err());
        candidate.domains.truncate(1);

        candidate.domains[0]
            .peer_protocols
            .push("edge_a".to_owned());
        assert!(candidate.validate().is_err());

        let mut timeout_candidate = config(std::path::Path::new("/tmp"));
        timeout_candidate.command_timeout = BIRD_COMMAND_TIMEOUT_MAX + Duration::from_secs(1);
        assert!(timeout_candidate.validate().is_err());

        let mut peer_candidate = config(std::path::Path::new("/tmp"));
        peer_candidate.domains[0].peer_protocols = (0..=MAX_BIRD_PEERS_PER_DOMAIN)
            .map(|index| format!("peer_{index}"))
            .collect();
        assert!(peer_candidate.validate().is_err());

        let mut domain_candidate = config(std::path::Path::new("/tmp"));
        domain_candidate.domains = (0..=MAX_ADVERTISEMENT_ROUTING_DOMAINS)
            .map(|index| BirdDomainBinding {
                domain: RoutingDomainTag::new(index as u64 + 1),
                static_protocol: format!("static_{index}"),
                peer_protocols: Vec::new(),
            })
            .collect();
        assert!(domain_candidate.validate().is_err());

        let mut total_peer_candidate = config(std::path::Path::new("/tmp"));
        total_peer_candidate.domains = (0..2)
            .map(|domain_index| BirdDomainBinding {
                domain: RoutingDomainTag::new(domain_index + 1),
                static_protocol: format!("static_{domain_index}"),
                peer_protocols: (0..17)
                    .map(|peer_index| format!("peer_{domain_index}_{peer_index}"))
                    .collect(),
            })
            .collect();
        assert_eq!(MAX_BIRD_PEERS_TOTAL, 32);
        assert!(total_peer_candidate.validate().is_err());
    }
}
