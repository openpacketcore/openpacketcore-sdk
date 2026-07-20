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
//! from `show protocols all` and BFD path health from `show bfd sessions`,
//! correlated by neighbor address; the adapter never touches BGP or BFD wire
//! protocols itself.
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
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::error::IpsecLbError;
use crate::model::IpAddress;
use crate::ownership::RoutingDomainTag;
use crate::routing::{
    HostPrefix, PathHealth, PeerIdentity, PeerObservation, PeerSessionState, PrefixApplyOutcome,
    PrefixRejectReason, RoutingStackAdapter, RoutingStackKind, RoutingStackProbe,
};

const MAX_PROTOCOL_NAME_LEN: usize = 64;
const BIRD_REPLY_LINE_MAX: usize = 4096;
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
        if self.domains.is_empty() {
            return Err(IpsecLbError::invalid_config(
                "domains",
                "at least one routing-domain binding is required",
            ));
        }
        if self.command_timeout.is_zero() {
            return Err(IpsecLbError::invalid_config(
                "command_timeout",
                "command timeout must be non-zero",
            ));
        }
        let mut domains = BTreeSet::new();
        let mut protocols = BTreeSet::new();
        for binding in &self.domains {
            if !domains.insert(binding.domain) {
                return Err(IpsecLbError::invalid_config(
                    "domains",
                    "duplicate routing-domain binding",
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

/// Adapter toward a BIRD routing daemon over its control socket.
#[derive(Debug, Clone)]
pub struct BirdControlSocketAdapter {
    config: BirdAdapterConfig,
    /// Last successfully read BFD health per neighbor. `show bfd sessions`
    /// failures degrade to the cache instead of flapping every peer to
    /// `Unknown`, so path-health events fire only on real transitions.
    bfd_health_cache: std::sync::Arc<std::sync::Mutex<BTreeMap<IpAddress, PathHealth>>>,
}

impl BirdControlSocketAdapter {
    /// Build an adapter from a validated configuration.
    pub fn new(config: BirdAdapterConfig) -> Result<Self, IpsecLbError> {
        config.validate()?;
        Ok(Self {
            config,
            bfd_health_cache: std::sync::Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        })
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

    /// Run one control-socket command and return its content lines (reply
    /// codes stripped, code-collapsed continuations reattached) plus the
    /// final reply code.
    async fn command(&self, command: &str) -> Result<BirdReply, BirdCommandError> {
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
            let mut last_code = 0u16;
            loop {
                let line = read_reply_line(&mut reader).await?;
                match classify_reply_line(&line, &mut last_code) {
                    ReplyLine::Content(text) => lines.push(text),
                    ReplyLine::Progress => {}
                    ReplyLine::Final(code, text) => {
                        if code >= 8000 {
                            return Err(BirdCommandError::Refused(code));
                        }
                        if !text.is_empty() {
                            lines.push(text);
                        }
                        return Ok(BirdReply { code, lines });
                    }
                }
            }
        };
        tokio::time::timeout(self.config.command_timeout, operation())
            .await
            .map_err(|_| {
                BirdCommandError::io(
                    "bird_command",
                    io::Error::new(io::ErrorKind::TimedOut, "BIRD command timed out"),
                )
            })?
    }

    fn fragment_path(&self, binding: &BirdDomainBinding) -> PathBuf {
        self.config
            .fragment_dir
            .join(format!("{}.conf", binding.static_protocol))
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
        let path = self.fragment_path(binding);
        if desired.is_empty() {
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(IpsecLbError::io("bird_fragment_remove", error)),
            }
        } else {
            let fragment = render_fragment(binding, desired);
            write_file_atomic(&path, fragment.as_bytes()).await?;
        }
        match self.command("configure soft").await {
            Ok(reply) => Ok(FragmentApply::Replied(reply.code)),
            Err(BirdCommandError::Io(_error)) => Ok(FragmentApply::Ambiguous),
            Err(BirdCommandError::Refused(code)) => Ok(FragmentApply::Refused(code)),
        }
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

/// Write a file atomically: sibling temporary file, flush and fsync, rename.
///
/// A crash mid-write can then never leave a truncated fragment that would
/// fail the operator's entire BIRD configuration on the next reconfigure.
async fn write_file_atomic(path: &std::path::Path, contents: &[u8]) -> Result<(), IpsecLbError> {
    let tmp_path = path.with_extension("tmp");
    let write_result = async {
        let mut file = tokio::fs::File::create(&tmp_path).await?;
        file.write_all(contents).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&tmp_path, path).await?;
        // Best-effort directory fsync so the rename itself is durable.
        if let Some(parent) = path.parent() {
            if let Ok(dir) = tokio::fs::File::open(parent).await {
                let _ = dir.sync_all().await;
            }
        }
        Ok::<(), io::Error>(())
    }
    .await;
    if let Err(error) = write_result {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(IpsecLbError::io("bird_fragment_write", error));
    }
    Ok(())
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
    let mut fragment = String::from("# generated by opc-ipsec-lb; do not edit\n");
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
                    protocol.neighbor_address = parse_ip_address(address.trim());
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
        let Some(address) = tokens.next().and_then(parse_bfd_neighbor) else {
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

/// Parse a BFD neighbor address, dropping any `%zone` suffix BIRD prints
/// for link-local neighbors.
fn parse_bfd_neighbor(text: &str) -> Option<IpAddress> {
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

/// Extract originated prefixes from `show route protocol <name>` output.
fn parse_show_route_prefixes(output: &[String]) -> BTreeSet<String> {
    output
        .iter()
        .filter_map(|line| {
            let token = line.split_whitespace().next()?;
            token.contains('/').then(|| token.to_owned())
        })
        .collect()
}

#[async_trait]
impl RoutingStackAdapter for BirdControlSocketAdapter {
    async fn apply_advertisement_set(
        &self,
        domain: RoutingDomainTag,
        desired: &BTreeSet<HostPrefix>,
    ) -> Result<BTreeMap<HostPrefix, PrefixApplyOutcome>, IpsecLbError> {
        let binding = self.binding(domain)?;
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

        let configure_code = match self.apply_fragment(binding, desired).await? {
            FragmentApply::Ambiguous => {
                // Mid-command disconnect, timeout, or EOF in the configure
                // leg: BIRD may or may not have applied the fragment. This
                // is ambiguous, never a definitive rejection.
                return Ok(unreachable());
            }
            FragmentApply::Refused(_code) => {
                return Ok(rejected(PrefixRejectReason::ConfigureFailed));
            }
            FragmentApply::Replied(code) => code,
        };
        if configure_code != REPLY_RECONFIGURED {
            // 0004/0005/0006 (queued/in-progress/ignored) and any other
            // non-refusal code: the reconfiguration may still land.
            return Ok(unreachable());
        }
        if desired.is_empty() {
            return Ok(BTreeMap::new());
        }
        match self
            .command(&format!("show route protocol {}", binding.static_protocol))
            .await
        {
            Ok(reply) => {
                let originated = parse_show_route_prefixes(&reply.lines);
                Ok(desired
                    .iter()
                    .map(|prefix| {
                        let outcome = if originated.contains(&render_prefix(*prefix)) {
                            PrefixApplyOutcome::Accepted
                        } else {
                            PrefixApplyOutcome::Rejected(PrefixRejectReason::StackRejected)
                        };
                        (*prefix, outcome)
                    })
                    .collect())
            }
            Err(BirdCommandError::Io(_error)) => Ok(unreachable()),
            Err(BirdCommandError::Refused(_code)) => {
                Ok(rejected(PrefixRejectReason::StackRejected))
            }
        }
    }

    async fn withdraw_all(&self, domain: RoutingDomainTag) -> Result<(), IpsecLbError> {
        let binding = self.binding(domain)?;
        match self.apply_fragment(binding, &BTreeSet::new()).await? {
            FragmentApply::Replied(code) if code == REPLY_RECONFIGURED => Ok(()),
            FragmentApply::Replied(_code) => Err(IpsecLbError::io(
                "bird_configure",
                io::Error::other("BIRD reconfiguration is queued or in progress"),
            )),
            FragmentApply::Ambiguous => Err(IpsecLbError::io(
                "bird_configure",
                io::Error::other("BIRD configure command result is unknown"),
            )),
            FragmentApply::Refused(_code) => Err(IpsecLbError::io(
                "bird_configure",
                io::Error::other("BIRD refused the reconfiguration"),
            )),
        }
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
        // failed read degrades to the last successfully read health table
        // instead of flapping every peer to Unknown.
        let bfd_health: BTreeMap<IpAddress, PathHealth> =
            match self.command("show bfd sessions").await {
                Ok(reply) => {
                    let fresh = parse_show_bfd_sessions(&reply.lines);
                    *self
                        .bfd_health_cache
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = fresh.clone();
                    fresh
                }
                Err(_) => self
                    .bfd_health_cache
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone(),
            };
        let protocols = parse_show_protocols_all(&protocols_reply.lines);
        let mut observations = Vec::new();
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
                    observations.push(PeerObservation {
                        domain: binding.domain,
                        peer,
                        session: protocol.session,
                        path_health,
                    });
                }
            }
        }
        Ok(observations)
    }

    async fn probe(&self) -> Result<RoutingStackProbe, IpsecLbError> {
        match self.command("show status").await {
            Ok(_reply) => Ok(RoutingStackProbe {
                kind: RoutingStackKind::Bird,
                stack_reachable: true,
                mutation_ready: true,
                details: Some("BIRD control socket reachable".to_owned()),
            }),
            Err(_error) => Ok(RoutingStackProbe {
                kind: RoutingStackKind::Bird,
                stack_reachable: false,
                mutation_ready: false,
                details: Some("BIRD control socket unreachable".to_owned()),
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
        BirdAdapterConfig {
            socket_path: dir.join("bird.ctl"),
            fragment_dir: dir.join("opc.d"),
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
        let adapter = BirdControlSocketAdapter::new(config(&dir)).unwrap();

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
                    "     Neighbor address: 203.0.113.1\n",
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
                    " 203.0.113.1               eth0       Up         10:00:00.000  0.050     0.250\n",
                    " 203.0.113.2               eth0       Down       10:00:00.000  0.050     0.250\n",
                    "0000 \n",
                ],
            ),
        ]);
        let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
        let adapter = BirdControlSocketAdapter::new(config(&dir)).unwrap();

        let observations = adapter.poll_observations().await.unwrap();
        assert_eq!(observations.len(), 2);
        let edge_a = observations
            .iter()
            .find(|obs| obs.peer.name() == "edge_a")
            .unwrap();
        assert_eq!(edge_a.session, PeerSessionState::Established);
        assert_eq!(edge_a.path_health, PathHealth::Up);
        assert_eq!(edge_a.peer.address(), Some(IpAddress::V4([203, 0, 113, 1])));
        let edge_b = observations
            .iter()
            .find(|obs| obs.peer.name() == "edge_b")
            .unwrap();
        assert_eq!(edge_b.session, PeerSessionState::Connecting);
        assert_eq!(edge_b.path_health, PathHealth::Down);

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
        ]);
        let _server = spawn_mock_bird(dir.join("bird.ctl"), Arc::clone(&scripts)).await;
        let adapter = BirdControlSocketAdapter::new(config(&dir)).unwrap();

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
        let adapter = BirdControlSocketAdapter::new(config(&dir)).unwrap();
        let outcomes = adapter
            .apply_advertisement_set(binding().domain, &desired)
            .await
            .unwrap();
        assert_eq!(
            outcomes.values().collect::<Vec<_>>(),
            vec![&PrefixApplyOutcome::Accepted]
        );
        // The fragment landed atomically: no temporary file remains.
        assert!(dir.join("opc.d/opc_adv_64512.conf").exists());
        assert!(!dir.join("opc.d/opc_adv_64512.tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();

        // 0004 Reconfiguration in progress: ambiguous, never a rejection.
        let dir = test_dir("configure-queued");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let scripts = script_map(&[("configure soft", &["0004 Reconfiguration in progress\n"])]);
        let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
        let adapter = BirdControlSocketAdapter::new(config(&dir)).unwrap();
        let outcomes = adapter
            .apply_advertisement_set(binding().domain, &desired)
            .await
            .unwrap();
        assert_eq!(
            outcomes.values().collect::<Vec<_>>(),
            vec![&PrefixApplyOutcome::Unreachable]
        );
        std::fs::remove_dir_all(&dir).unwrap();

        // 9xxx refusal: the only ConfigureFailed path.
        let dir = test_dir("configure-refused");
        std::fs::create_dir_all(dir.join("opc.d")).unwrap();
        let scripts = script_map(&[("configure soft", &["9001 Parse error\n"])]);
        let _server = spawn_mock_bird(dir.join("bird.ctl"), scripts).await;
        let adapter = BirdControlSocketAdapter::new(config(&dir)).unwrap();
        let outcomes = adapter
            .apply_advertisement_set(binding().domain, &desired)
            .await
            .unwrap();
        assert_eq!(
            outcomes.values().collect::<Vec<_>>(),
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
        let adapter = BirdControlSocketAdapter::new(config(&dir)).unwrap();
        let desired: BTreeSet<HostPrefix> = [HostPrefix::new(IpAddress::V4([203, 0, 113, 10]))]
            .into_iter()
            .collect();
        let outcomes = adapter
            .apply_advertisement_set(binding().domain, &desired)
            .await
            .unwrap();
        assert_eq!(
            outcomes.values().collect::<Vec<_>>(),
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
    fn show_route_parses_originated_prefixes() {
        let output: Vec<String> = [
            "Table master4:",
            "203.0.113.10/32    blackhole [opc_adv_64512 10:00:00] * (200)",
            "198.51.100.7/32    blackhole [opc_adv_64512 10:00:00] * (200)",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        let prefixes = parse_show_route_prefixes(&output);
        assert!(prefixes.contains("203.0.113.10/32"));
        assert!(prefixes.contains("198.51.100.7/32"));
        assert!(!prefixes.contains("Table"));
    }

    #[test]
    fn config_validation_rejects_bad_symbols_and_duplicates() {
        let mut config = BirdAdapterConfig {
            socket_path: PathBuf::from("/run/bird/bird.ctl"),
            fragment_dir: PathBuf::from("/etc/bird/opc.d"),
            domains: vec![binding()],
            command_timeout: Duration::from_secs(10),
        };
        config.validate().unwrap();

        config.domains[0].static_protocol = "bad name;".to_owned();
        assert!(config.validate().is_err());
        config.domains[0].static_protocol = "opc_adv_64512".to_owned();

        config.domains.push(config.domains[0].clone());
        assert!(config.validate().is_err());
        config.domains.truncate(1);

        config.domains[0].peer_protocols.push("edge_a".to_owned());
        assert!(config.validate().is_err());
    }
}
