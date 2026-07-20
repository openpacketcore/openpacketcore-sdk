//! BIRD routing-daemon adapter over the BIRD control socket.
//!
//! The BIRD remote-control protocol is a stable, documented line protocol on
//! a UNIX domain socket ("you do not necessarily need to use `birdc` to talk
//! to BIRD, your own applications could do that, too" — BIRD User's Guide,
//! Remote control). This adapter speaks it directly with no new dependencies
//! and never shells out to `birdc`.
//!
//! Advertisement intent is realized as one generated `protocol static`
//! fragment per routing domain (host routes only) applied with
//! `configure soft`; the operator's main configuration includes the fragment
//! directory and owns all BGP peer, ASN, policy, and BFD setup. The fragment
//! is always rendered from the exact desired set, so the adapter can never
//! originate anything outside it. Per-peer session state and BFD path health
//! are relayed from `show protocols all` output; the adapter never touches
//! BGP or BFD wire protocols itself.

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

/// Binding between one opaque routing-domain tag and operator-owned BIRD
/// protocol instances.
///
/// `static_protocol` names the generated `protocol static` instance that
/// carries this domain's host routes; `peer_protocols` names the
/// operator-configured BGP instances whose sessions and BFD state the
/// adapter relays. The adapter never creates, selects, or configures peers.
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

/// Adapter toward a BIRD routing daemon over its control socket.
#[derive(Debug, Clone)]
pub struct BirdControlSocketAdapter {
    config: BirdAdapterConfig,
}

impl BirdControlSocketAdapter {
    /// Build an adapter from a validated configuration.
    pub fn new(config: BirdAdapterConfig) -> Result<Self, IpsecLbError> {
        config.validate()?;
        Ok(Self { config })
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

    /// Run one control-socket command and return its content lines with
    /// reply codes stripped.
    async fn command(&self, command: &str) -> Result<Vec<String>, IpsecLbError> {
        let operation = || async {
            let stream = UnixStream::connect(&self.config.socket_path)
                .await
                .map_err(|error| IpsecLbError::io("bird_connect", error))?;
            let mut reader = BufReader::new(stream);

            let greeting = read_reply_line(&mut reader).await?;
            if !greeting.starts_with("0001") {
                return Err(IpsecLbError::io(
                    "bird_greeting",
                    io::Error::new(io::ErrorKind::InvalidData, "unexpected BIRD greeting"),
                ));
            }

            let mut line_bytes = command.as_bytes().to_vec();
            line_bytes.push(b'\n');
            reader
                .get_mut()
                .write_all(&line_bytes)
                .await
                .map_err(|error| IpsecLbError::io("bird_command_write", error))?;

            let mut lines = Vec::new();
            loop {
                let line = read_reply_line(&mut reader).await?;
                match parse_reply_line(&line) {
                    Some((code, _continuation, text)) => {
                        // 0002 ("reading configuration") is progress, never
                        // the final reply of a configure command.
                        let final_reply =
                            line.as_bytes().get(4).is_none_or(|b| *b != b'-') && code != 2;
                        if final_reply {
                            if code >= 8000 {
                                return Err(IpsecLbError::io(
                                    "bird_command",
                                    io::Error::other("BIRD rejected the control command"),
                                ));
                            }
                            if !text.is_empty() {
                                lines.push(text.to_owned());
                            }
                            return Ok(lines);
                        }
                        lines.push(text.to_owned());
                    }
                    None => lines.push(line),
                }
            }
        };
        tokio::time::timeout(self.config.command_timeout, operation())
            .await
            .map_err(|_| {
                IpsecLbError::io(
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

    async fn apply_fragment(
        &self,
        binding: &BirdDomainBinding,
        desired: &BTreeSet<HostPrefix>,
    ) -> Result<(), IpsecLbError> {
        let path = self.fragment_path(binding);
        if desired.is_empty() {
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(IpsecLbError::io("bird_fragment_remove", error)),
            }
        } else {
            let fragment = render_fragment(binding, desired);
            tokio::fs::write(&path, fragment)
                .await
                .map_err(|error| IpsecLbError::io("bird_fragment_write", error))?;
        }
        self.command("configure soft").await?;
        Ok(())
    }
}

async fn read_reply_line(reader: &mut BufReader<UnixStream>) -> Result<String, IpsecLbError> {
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .await
        .map_err(|error| IpsecLbError::io("bird_command_read", error))?;
    if read == 0 {
        return Err(IpsecLbError::io(
            "bird_command_read",
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "BIRD closed the control socket",
            ),
        ));
    }
    if line.len() > BIRD_REPLY_LINE_MAX {
        return Err(IpsecLbError::io(
            "bird_command_read",
            io::Error::new(io::ErrorKind::InvalidData, "BIRD reply line too long"),
        ));
    }
    Ok(line.trim_end().to_owned())
}

/// Parse one BIRD reply line into (code, continuation, text).
fn parse_reply_line(line: &str) -> Option<(u16, bool, &str)> {
    let bytes = line.as_bytes();
    if bytes.len() < 5 {
        return None;
    }
    let code: u16 = line.get(..4)?.parse().ok()?;
    let separator = bytes[4];
    match separator {
        b' ' => Some((code, false, line.get(5..).unwrap_or_default())),
        b'-' => Some((code, true, line.get(5..).unwrap_or_default())),
        _ => None,
    }
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
    up: bool,
    info: String,
    neighbor_address: Option<IpAddress>,
    bfd: Option<PathHealth>,
}

/// Parse `show protocols all` output into protocol blocks.
///
/// Block headers are unindented rows of the shape
/// `name proto table state since info...` where `state` is `up` or `down`;
/// detail lines are indented. The column header row is excluded because its
/// fourth token is `State`.
fn parse_show_protocols_all(output: &[String]) -> Vec<ParsedProtocol> {
    let mut protocols: Vec<ParsedProtocol> = Vec::new();
    for line in output {
        if line.starts_with(char::is_whitespace) {
            let detail = line.trim();
            if let Some(protocol) = protocols.last_mut() {
                if let Some(address) = detail.strip_prefix("Neighbor address:") {
                    protocol.neighbor_address = parse_ip_address(address.trim());
                } else if let Some(bfd) = detail.strip_prefix("BFD:") {
                    protocol.bfd = Some(parse_bfd_state(bfd.trim()));
                }
            }
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() >= 5 && matches!(tokens[3], "up" | "down") {
            protocols.push(ParsedProtocol {
                name: tokens[0].to_owned(),
                up: tokens[3] == "up",
                info: tokens[5..].join(" "),
                neighbor_address: None,
                bfd: None,
            });
        }
    }
    protocols
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

fn parse_session_state(up: bool, info: &str) -> PeerSessionState {
    if !up {
        return PeerSessionState::Down;
    }
    if info.starts_with("Established") {
        PeerSessionState::Established
    } else {
        PeerSessionState::Connecting
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
        if let Err(_error) = self.apply_fragment(binding, desired).await {
            // The fragment write or reconfigure failed before the stack
            // confirmed anything: every prefix is rejected with the
            // configuration failure.
            return Ok(desired
                .iter()
                .map(|prefix| {
                    (
                        *prefix,
                        PrefixApplyOutcome::Rejected(PrefixRejectReason::ConfigureFailed),
                    )
                })
                .collect());
        }
        if desired.is_empty() {
            return Ok(BTreeMap::new());
        }
        let verify = self
            .command(&format!("show route protocol {}", binding.static_protocol))
            .await;
        match verify {
            Ok(output) => {
                let originated = parse_show_route_prefixes(&output);
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
            Err(_error) => Ok(desired
                .iter()
                .map(|prefix| (*prefix, PrefixApplyOutcome::Unreachable))
                .collect()),
        }
    }

    async fn withdraw_all(&self, domain: RoutingDomainTag) -> Result<(), IpsecLbError> {
        let binding = self.binding(domain)?;
        self.apply_fragment(binding, &BTreeSet::new()).await
    }

    async fn poll_observations(&self) -> Result<Vec<PeerObservation>, IpsecLbError> {
        let output = self.command("show protocols all").await?;
        let protocols = parse_show_protocols_all(&output);
        let mut observations = Vec::new();
        for binding in &self.config.domains {
            for peer_name in &binding.peer_protocols {
                if let Some(protocol) = protocols.iter().find(|p| &p.name == peer_name) {
                    let peer = PeerIdentity::named(protocol.name.clone());
                    let peer = match protocol.neighbor_address {
                        Some(address) => peer.with_address(address),
                        None => peer,
                    };
                    observations.push(PeerObservation {
                        domain: binding.domain,
                        peer,
                        session: parse_session_state(protocol.up, &protocol.info),
                        path_health: protocol.bfd.unwrap_or(PathHealth::Unknown),
                    });
                }
            }
        }
        Ok(observations)
    }

    async fn probe(&self) -> Result<RoutingStackProbe, IpsecLbError> {
        match self.command("show status").await {
            Ok(_status) => Ok(RoutingStackProbe {
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

    fn binding() -> BirdDomainBinding {
        BirdDomainBinding {
            domain: RoutingDomainTag::new(64512),
            static_protocol: "opc_adv_64512".to_owned(),
            peer_protocols: vec!["edge_a".to_owned(), "edge_b".to_owned()],
        }
    }

    #[test]
    fn reply_line_parsing_handles_codes_and_continuation() {
        assert_eq!(
            parse_reply_line("0001 BIRD 2.13 ready."),
            Some((1, false, "BIRD 2.13 ready."))
        );
        assert_eq!(
            parse_reply_line("2002-Name       Proto"),
            Some((2002, true, "Name       Proto"))
        );
        assert_eq!(parse_reply_line("0000 "), Some((0, false, "")));
        assert_eq!(parse_reply_line("not a reply"), None);
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
    fn show_protocols_all_parses_sessions_and_bfd() {
        let output: Vec<String> = [
            "Name       Proto      Table      State  Since         Info",
            "device1    Device     ---        up     2024-01-01",
            "edge_a     BGP        ---        up     10:00:00      Established",
            "  Description:    upstream edge a",
            "  BGP state:          Established",
            "    Neighbor address: 203.0.113.1",
            "    Neighbor AS:      64512",
            "  BFD:                Up",
            "edge_b     BGP        ---        up     10:00:01      Active",
            "    Neighbor address: 203.0.113.2",
            "    Neighbor AS:      64513",
            "  BFD:                Down",
            "kernel1    Kernel     master4    up     2024-01-01",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        let protocols = parse_show_protocols_all(&output);
        let edge_a = protocols.iter().find(|p| p.name == "edge_a").unwrap();
        assert_eq!(
            parse_session_state(edge_a.up, &edge_a.info),
            PeerSessionState::Established
        );
        assert_eq!(
            edge_a.neighbor_address,
            Some(IpAddress::V4([203, 0, 113, 1]))
        );
        assert_eq!(edge_a.bfd, Some(PathHealth::Up));
        let edge_b = protocols.iter().find(|p| p.name == "edge_b").unwrap();
        assert_eq!(
            parse_session_state(edge_b.up, &edge_b.info),
            PeerSessionState::Connecting
        );
        assert_eq!(edge_b.bfd, Some(PathHealth::Down));
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
